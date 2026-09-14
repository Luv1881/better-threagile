#!/usr/bin/env python3
"""Measure how close a bootstrapped starter model is to a hand-authored model.

For every project in the corpus this runs `threagile bootstrap` against the
project's infrastructure (compose / k8s / openapi / terraform) and compares the
result with the project's real, committed threat model.

Metrics (0..1 each, aggregated across projects — a change that helps one
project but hurts another is overfitting and must not land):

  assets.coverage      share of reference technical assets present
  assets.precision     share of bootstrapped technical assets in the reference
  assets.type_agreement  share of matched assets with the same asset type
  boundaries.coverage  share of reference trust boundaries present
  data_assets.coverage share of reference data assets represented

Matching is on normalised titles first, then structurally: a trust boundary
matches when it contains the same matched technical assets (≥50% of the
reference side's matched assets); a data asset matches when it is processed or
stored by the same matched technical assets. Names in starter models naturally
differ from hand-authored ones, so structural evidence is what makes the
comparison meaningful — and it cannot be gamed by renaming.

Usage:
    THREAGILE=/path/to/threagile python3 test/fidelity/compare.py corpus.tsv
    ... --md results.md --json results.json [--verbose]

Corpus file format (tab-separated, # comments allowed):
    project <TAB> reference-model.yaml <TAB> infrastructure-dir-to-scan
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile

import yaml


def normalize(title) -> str:
    return re.sub(r"[^a-z0-9]", "", str(title).lower())


def load_model(path: str, seen: set | None = None) -> dict:
    """Load a model, resolving the fork's includes: directive (multi-file models)."""
    seen = seen or set()
    resolved_path = os.path.realpath(path)
    if resolved_path in seen:
        return {}
    seen.add(resolved_path)
    with open(path) as handle:
        model = yaml.safe_load(handle) or {}
    includes = model.pop("includes", None) or []
    for include in includes:
        included_path = os.path.join(os.path.dirname(path), include)
        included = load_model(included_path, seen)
        for key, value in included.items():
            if isinstance(value, dict) and isinstance(model.get(key), dict):
                model[key].update(value)
            elif isinstance(value, list) and isinstance(model.get(key), list):
                model[key] = model[key] + value
            elif key not in model or model[key] in (None, {}, [""]):
                model[key] = value
    return model


def entries(model: dict, key: str) -> dict:
    raw = model.get(key) or {}
    if not isinstance(raw, dict):
        return {}
    return {str(title): (value if isinstance(value, dict) else {}) for title, value in raw.items()}


def entity_ids(entities: dict) -> dict:
    """id -> title, so references written as IDs resolve to their entity."""
    by_id = {}
    for title, value in entities.items():
        entity_id = value.get("id")
        if entity_id:
            by_id[str(entity_id)] = title
    return by_id


def title_match(ref_title: str, candidates: list) -> str | None:
    norm = normalize(ref_title)
    for candidate in candidates:
        if normalize(candidate) == norm:
            return candidate
    if len(norm) >= 5:
        for candidate in candidates:
            candidate_norm = normalize(candidate)
            if len(candidate_norm) < 5:
                continue
            shorter, longer = sorted((norm, candidate_norm), key=len)
            if longer and shorter in longer and len(shorter) / len(longer) >= 0.5:
                return candidate
    return None


def overlap(ref_set: set, gen_set: set) -> float:
    """How much of the reference set is covered by the generated set.

    A generated entity that holds far more assets than the reference one is
    treated as a catch-all (namespace/default boundaries) and matches nothing:
    otherwise one big boundary could absorb every reference boundary.
    """
    if not ref_set or not gen_set:
        return 0.0
    if len(gen_set) > 2 * len(ref_set):
        return 0.0
    return len(ref_set & gen_set) / len(ref_set)


def match_entities(ref_entities: dict, gen_entities: dict, ref_sets=None, gen_sets=None) -> tuple[list, list, list]:
    """Match by title first, then structurally via entity sets. Greedy, 1:1."""
    matched, missing, used = [], [], set()

    for ref_title in ref_entities:
        available = [title for title in gen_entities if title not in used]
        gen_title = title_match(ref_title, available)
        if gen_title:
            matched.append((ref_title, gen_title))
            used.add(gen_title)
        else:
            missing.append(ref_title)

    if ref_sets is not None and gen_sets is not None:
        still_missing = list(missing)
        missing = []
        for ref_title in still_missing:
            best_title, best_score = None, 0.0
            for gen_title in gen_entities:
                if gen_title in used:
                    continue
                score = overlap(ref_sets.get(ref_title, set()), gen_sets.get(gen_title, set()))
                if score > best_score:
                    best_title, best_score = gen_title, score
            if best_title and best_score >= 0.5:
                matched.append((ref_title, best_title))
                used.add(best_title)
            else:
                missing.append(ref_title)

    extra = [title for title in gen_entities if title not in used]
    return matched, missing, extra


def translate_ref_assets(asset_matches: list, ref_ta: dict, gen_ta: dict) -> dict:
    """ref technical asset id AND title -> matched generated title."""
    ref_by_id = entity_ids(ref_ta)
    translation = {}
    for ref_title, gen_title in asset_matches:
        translation[ref_title] = gen_title
        ref_id = (ref_ta.get(ref_title) or {}).get("id")
        if ref_id:
            translation[str(ref_id)] = gen_title
    for ref_id, ref_title in ref_by_id.items():
        if ref_title in translation:
            translation[ref_id] = translation[ref_title]
    return translation


def boundary_set(ref_model_index, translation=None) -> dict:
    """boundary title -> set of (translated) technical asset titles inside it."""
    ta_by_id = entity_ids(ref_model_index["ta"])
    sets = {}
    for title, boundary in ref_model_index["tb"].items():
        inside = boundary.get("technical_assets_inside") or []
        resolved = set()
        for reference in inside:
            asset_title = ta_by_id.get(str(reference), str(reference))
            if translation is not None:
                asset_title = translation.get(asset_title, translation.get(str(reference)))
                if asset_title is None:
                    continue
            resolved.add(normalize(asset_title))
        sets[title] = resolved
    return sets


def data_asset_hosts(ref_model_index, translation=None) -> dict:
    """data asset title -> set of (translated) technical asset titles using it."""
    ta_by_id = entity_ids(ref_model_index["ta"])
    da_by_id = entity_ids(ref_model_index["da"])
    hosts = {title: set() for title in ref_model_index["da"]}

    def data_asset_title(reference) -> str | None:
        key = str(reference)
        return da_by_id.get(key, key if key in hosts else None)

    def technical_asset_title(reference) -> str | None:
        asset_title = ta_by_id.get(str(reference), str(reference))
        if translation is not None:
            asset_title = translation.get(asset_title, translation.get(str(reference)))
        return asset_title

    for asset_title, asset in ref_model_index["ta"].items():
        host = normalize(translation.get(asset_title, asset_title) if translation else asset_title)
        for key in ("data_assets_processed", "data_assets_stored"):
            for reference in asset.get(key) or []:
                data_title = data_asset_title(reference)
                if data_title and data_title in hosts:
                    hosts[data_title].add(host)
        for link in (asset.get("communication_links") or {}).values():
            if not isinstance(link, dict):
                continue
            for key in ("data_assets_sent", "data_assets_received"):
                for reference in link.get(key) or []:
                    data_title = data_asset_title(reference)
                    if data_title and data_title in hosts:
                        hosts[data_title].add(host)
    return hosts


def index(model: dict) -> dict:
    return {
        "ta": entries(model, "technical_assets"),
        "tb": entries(model, "trust_boundaries"),
        "da": entries(model, "data_assets"),
    }


def class_metrics(ref_entities, gen_entities, ref_sets=None, gen_sets=None, with_types=False) -> dict:
    matched, missing, extra = match_entities(ref_entities, gen_entities, ref_sets, gen_sets)
    metrics = {
        "ref": len(ref_entities),
        "generated": len(gen_entities),
        "matched": len(matched),
        "missing": missing,
        "extra": extra,
        "coverage": round(len(matched) / len(ref_entities), 3) if ref_entities else None,
        "precision": round(len(matched) / len(gen_entities), 3) if gen_entities else None,
    }
    if with_types:
        agree = sum(
            1
            for ref_title, gen_title in matched
            if (ref_entities[ref_title] or {}).get("type") == (gen_entities[gen_title] or {}).get("type")
        )
        metrics["type_agreement"] = round(agree / len(matched), 3) if matched else None
    return metrics


def bootstrap(binary: str, iac_dir: str, output: str) -> tuple[bool, str]:
    result = subprocess.run(
        [binary, "bootstrap", "--dir", iac_dir, "--output", output, "--policy-profile", ""],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return False, (result.stderr or result.stdout).strip()
    return True, ""


def compare_project(binary: str, name: str, ref_path: str, iac_dir: str, workdir: str) -> dict:
    generated_path = os.path.join(workdir, f"{name}.yaml")
    ok, error = bootstrap(binary, iac_dir, generated_path)
    if not ok:
        return {"project": name, "error": error}

    ref_model, gen_model = load_model(ref_path), load_model(generated_path)
    ref_index, gen_index = index(ref_model), index(gen_model)

    assets = class_metrics(ref_index["ta"], gen_index["ta"], with_types=True)
    translation = translate_ref_assets(
        [(ref_title, gen_title) for ref_title, gen_title in match_entities(ref_index["ta"], gen_index["ta"])[0]],
        ref_index["ta"],
        gen_index["ta"],
    )

    # Boundaries: title match, then structural (same matched assets inside).
    ref_boundaries = ref_index["tb"]
    gen_boundaries = gen_index["tb"]
    boundary_structural = False
    if ref_boundaries:
        ref_sets = boundary_set(ref_index, translation)
        gen_sets = boundary_set(gen_index)
        boundaries = class_metrics(ref_boundaries, gen_boundaries, ref_sets, gen_sets)
        boundary_structural = True
    else:
        boundaries = class_metrics(ref_boundaries, gen_boundaries)

    # Data assets: title match, then structural (same matched assets host them).
    ref_data = ref_index["da"]
    gen_data = gen_index["da"]
    ref_host_sets = data_asset_hosts(ref_index, translation)
    gen_host_sets = data_asset_hosts(gen_index)
    data_assets = class_metrics(ref_data, gen_data, ref_host_sets, gen_host_sets)

    return {
        "project": name,
        "assets": assets,
        "boundaries": boundaries,
        "data_assets": data_assets,
        "boundary_structural": boundary_structural,
        "score": aggregate_score(assets, boundaries, data_assets),
    }


def aggregate_score(assets: dict, boundaries: dict, data_assets: dict) -> float:
    parts = []
    for metrics in (assets, boundaries, data_assets):
        if metrics["coverage"] is not None:
            parts.append(metrics["coverage"])
    if assets.get("precision") is not None:
        parts.append(assets["precision"])
    if assets.get("type_agreement") is not None:
        parts.append(assets["type_agreement"])
    return round(sum(parts) / len(parts), 3) if parts else 0.0


def fmt(value) -> str:
    return "-" if value is None else f"{value:.2f}"


def load_corpus(path: str) -> list[tuple[str, str, str]]:
    corpus = []
    with open(path) as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) != 3:
                sys.exit(f"bad corpus line: {line!r}")
            corpus.append((parts[0], os.path.expanduser(parts[1]), os.path.expanduser(parts[2])))
    return corpus


def render_markdown(results: list[dict]) -> str:
    lines = [
        "| Project | Assets coverage | Assets precision | Type agreement | Boundaries | Data assets | Score |",
        "|---|---|---|---|---|---|---|",
    ]
    for result in results:
        if "error" in result:
            lines.append(f"| {result['project']} | ERROR: {result['error']} | | | | | |")
            continue
        assets, boundaries, data = result["assets"], result["boundaries"], result["data_assets"]
        lines.append(
            "| {p} | {am}/{ar} ({ac}) | {ap} | {at} | {bm}/{br} ({bc}) | {dm}/{dr} ({dc}) | {score} |".format(
                p=result["project"],
                am=assets["matched"], ar=assets["ref"], ac=fmt(assets["coverage"]),
                ap=fmt(assets["precision"]), at=fmt(assets.get("type_agreement")),
                bm=boundaries["matched"], br=boundaries["ref"], bc=fmt(boundaries["coverage"]),
                dm=data["matched"], dr=data["ref"], dc=fmt(data["coverage"]),
                score=fmt(result["score"]),
            )
        )
    scored = [result["score"] for result in results if "error" not in result]
    if scored:
        lines.append(f"\nAggregate score: **{round(sum(scored) / len(scored), 3)}** over {len(scored)} projects")
    return "\n".join(lines)


def render_details(results: list[dict]) -> str:
    lines = []
    for result in results:
        if "error" in result:
            continue
        lines.append(f"\n## {result['project']}")
        for label, key in (("Technical assets", "assets"), ("Trust boundaries", "boundaries"), ("Data assets", "data_assets")):
            metrics = result[key]
            lines.append(f"\n{label}: coverage {fmt(metrics['coverage'])}, precision {fmt(metrics['precision'])}")
            if metrics.get("type_agreement") is not None:
                lines.append(f"Type agreement: {fmt(metrics['type_agreement'])}")
            if metrics["missing"]:
                lines.append(f"- missing from bootstrap ({len(metrics['missing'])}): {', '.join(sorted(metrics['missing'])[:20])}")
            if metrics["extra"]:
                lines.append(f"- extra in bootstrap ({len(metrics['extra'])}): {', '.join(sorted(metrics['extra'])[:20])}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("corpus", help="tab-separated corpus file")
    parser.add_argument("--md", help="write a markdown report here")
    parser.add_argument("--json", help="write raw results here")
    parser.add_argument("--binary", default=os.environ.get("THREAGILE", "threagile"))
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    results = []
    with tempfile.TemporaryDirectory(prefix="threagile-fidelity-") as workdir:
        for name, ref_path, iac_dir in load_corpus(args.corpus):
            if not os.path.exists(ref_path):
                results.append({"project": name, "error": f"reference model not found: {ref_path}"})
                continue
            if not os.path.isdir(iac_dir):
                results.append({"project": name, "error": f"infrastructure dir not found: {iac_dir}"})
                continue
            result = compare_project(args.binary, name, ref_path, iac_dir, workdir)
            results.append(result)
            if "error" in result:
                print(f"{name}: ERROR: {result['error']}", file=sys.stderr)
            else:
                print(f"{name}: score {result['score']:.3f}", file=sys.stderr)

    report = render_markdown(results)
    print(report)

    if args.verbose:
        print(render_details(results))
    if args.md:
        with open(args.md, "w") as handle:
            handle.write("# Bootstrap fidelity report\n\n")
            handle.write(report + "\n")
            handle.write(render_details(results) + "\n")
    if args.json:
        with open(args.json, "w") as handle:
            json.dump(results, handle, indent=2)


if __name__ == "__main__":
    main()
