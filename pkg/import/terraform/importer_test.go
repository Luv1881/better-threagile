package terraform

import (
	"testing"
)

const samplePlan = `{
  "format_version": "1.0",
  "values": {
    "root_module": {
      "resources": [
        {
          "address": "aws_s3_bucket.data",
          "type": "aws_s3_bucket",
          "name": "data",
          "provider_name": "registry.terraform.io/hashicorp/aws",
          "values": {
            "bucket": "my-data-bucket",
            "storage_encrypted": true
          }
        },
        {
          "address": "aws_lambda_function.worker",
          "type": "aws_lambda_function",
          "name": "worker",
          "provider_name": "registry.terraform.io/hashicorp/aws",
          "values": {
            "function_name": "my-worker",
            "dead_letter_config": [{"target_arn": "arn:aws:sqs:us-east-1:123:dlq"}]
          }
        },
        {
          "address": "aws_vpc.main",
          "type": "aws_vpc",
          "name": "main",
          "provider_name": "registry.terraform.io/hashicorp/aws",
          "values": {"cidr_block": "10.0.0.0/16"}
        },
        {
          "address": "aws_db_instance.prod",
          "type": "aws_db_instance",
          "name": "prod",
          "provider_name": "registry.terraform.io/hashicorp/aws",
          "values": {
            "identifier": "prod-db",
            "storage_encrypted": true,
            "backup_retention_period": 7
          }
        },
        {
          "address": "google_bigquery_dataset.unknown",
          "type": "google_bigquery_dataset",
          "name": "unknown",
          "provider_name": "registry.terraform.io/hashicorp/google",
          "values": {}
        }
      ]
    }
  }
}`

func TestImport_basic(t *testing.T) {
	model, err := Import([]byte(samplePlan), ImportOptions{SourceLabel: "test"})
	if err != nil {
		t.Fatalf("Import failed: %v", err)
	}

	// S3 bucket → object-storage datastore
	s3ID := "aws-s3-bucket-data-test"
	s3, ok := model.TechnicalAssets[s3ID]
	if !ok {
		t.Fatalf("expected asset %q", s3ID)
	}
	if len(s3.Technologies) == 0 || s3.Technologies[0].Name != "object-storage" {
		t.Errorf("expected object-storage technology, got %v", s3.Technologies)
	}

	// Lambda → serverless-function process
	lambdaID := "aws-lambda-function-worker-test"
	lambda, ok := model.TechnicalAssets[lambdaID]
	if !ok {
		t.Fatalf("expected asset %q", lambdaID)
	}
	if len(lambda.Technologies) == 0 || lambda.Technologies[0].Name != "serverless-function" {
		t.Errorf("expected serverless-function technology, got %v", lambda.Technologies)
	}

	// Lambda has DLQ → should have has-dlq tag
	if !containsTag(lambda.Tags, "has-dlq") {
		t.Errorf("expected has-dlq tag on lambda, got %v", lambda.Tags)
	}

	// VPC → trust boundary
	vpcID := "aws-vpc-main-test"
	if _, ok := model.TrustBoundaries[vpcID]; !ok {
		t.Errorf("expected trust boundary %q", vpcID)
	}

	// RDS → managed-database with has-automated-backup and has-encryption-at-rest
	dbID := "aws-db-instance-prod-test"
	db, ok := model.TechnicalAssets[dbID]
	if !ok {
		t.Fatalf("expected asset %q", dbID)
	}
	if !containsTag(db.Tags, "has-automated-backup") {
		t.Errorf("expected has-automated-backup tag, got %v", db.Tags)
	}
	if !containsTag(db.Tags, "has-encryption-at-rest") {
		t.Errorf("expected has-encryption-at-rest tag, got %v", db.Tags)
	}

	// Unknown resource type → silently skipped
	if _, ok := model.TechnicalAssets["google-bigquery-dataset-unknown-test"]; ok {
		t.Error("unknown resource type should be skipped")
	}
}

func TestImport_plannedValues(t *testing.T) {
	plan := `{"format_version":"1.0","planned_values":{"root_module":{"resources":[{"address":"aws_sqs_queue.events","type":"aws_sqs_queue","name":"events","provider_name":"registry.terraform.io/hashicorp/aws","values":{"name":"events"}}]}}}`
	model, err := Import([]byte(plan), ImportOptions{})
	if err != nil {
		t.Fatalf("Import from plan failed: %v", err)
	}
	if len(model.TechnicalAssets) == 0 {
		t.Error("expected at least one asset from planned_values")
	}
}

func TestImport_invalidJSON(t *testing.T) {
	_, err := Import([]byte("not json"), ImportOptions{})
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestImport_missingValuesKey(t *testing.T) {
	_, err := Import([]byte(`{"format_version":"1.0"}`), ImportOptions{})
	if err == nil {
		t.Error("expected error when neither values nor planned_values present")
	}
}

func containsTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}
