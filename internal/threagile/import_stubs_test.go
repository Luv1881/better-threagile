package threagile

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threagile/threagile/pkg/types"
)

// newTestModel builds a tiny synthetic model: an internet-facing external
// entity ("user") talking to a process ("api"), which talks to a datastore
// ("db"). Neither the process->datastore link nor the datastore itself
// carries any data asset, and the user->api link is internet-inbound (user
// has Internet: true) and also carries no data asset — exactly the shape a
// diagram importer produces.
func newTestModel() *types.Model {
	user := &types.TechnicalAsset{Id: "user", Title: "User", Type: types.ExternalEntity, Internet: true}
	api := &types.TechnicalAsset{Id: "api", Title: "Api Server", Type: types.Process}
	db := &types.TechnicalAsset{Id: "db", Title: "Db", Type: types.Datastore}

	link1 := &types.CommunicationLink{Id: "link-user-api", Title: "User to Api", SourceId: "user", TargetId: "api"}
	link2 := &types.CommunicationLink{Id: "link-api-db", Title: "Api to Db", SourceId: "api", TargetId: "db"}
	user.CommunicationLinks = []*types.CommunicationLink{link1}
	api.CommunicationLinks = []*types.CommunicationLink{link2}

	return &types.Model{
		TechnicalAssets: map[string]*types.TechnicalAsset{"user": user, "api": api, "db": db},
		DataAssets:      map[string]*types.DataAsset{},
		CommunicationLinks: map[string]*types.CommunicationLink{
			"link-user-api": link1,
			"link-api-db":   link2,
		},
	}
}

func TestStubDataAssetsCreatesDatastoreStub(t *testing.T) {
	m := newTestModel()
	stubDataAssets(m, "drawio")

	da, ok := m.DataAssets["db-data"]
	require.True(t, ok, "expected a stub data asset db-data")
	assert.Equal(t, "Db-data", da.Title)
	assert.Equal(t, types.Confidential, da.Confidentiality)
	assert.Equal(t, types.Critical, da.Integrity)
	assert.Equal(t, types.Critical, da.Availability)
	assert.Contains(t, da.Tags, "review-drawio")
	assert.Contains(t, da.Tags, "stub-data-asset")

	db := m.TechnicalAssets["db"]
	assert.Contains(t, db.DataAssetsStored, "db-data")

	link := m.CommunicationLinks["link-api-db"]
	assert.Contains(t, link.DataAssetsReceived, "db-data")
}

func TestStubDataAssetsCreatesInternetInboundLinkStub(t *testing.T) {
	m := newTestModel()
	stubDataAssets(m, "otm")

	da, ok := m.DataAssets["link-user-api-payload"]
	require.True(t, ok, "expected a stub payload data asset for the internet-inbound link")
	assert.Equal(t, "User to Api-payload", da.Title)
	assert.Contains(t, da.Tags, "review-otm")
	assert.Contains(t, da.Tags, "stub-data-asset")

	link := m.CommunicationLinks["link-user-api"]
	assert.Contains(t, link.DataAssetsSent, "link-user-api-payload")
}

func TestStubDataAssetsSkipsDatastoreThatAlreadyHasData(t *testing.T) {
	m := newTestModel()
	m.TechnicalAssets["db"].DataAssetsStored = []string{"real-data"}
	stubDataAssets(m, "drawio")

	_, exists := m.DataAssets["db-data"]
	assert.False(t, exists, "should not stub a datastore that already has data assets")
}

func TestStubDataAssetsSkipsLinkThatAlreadyHasData(t *testing.T) {
	m := newTestModel()
	m.CommunicationLinks["link-user-api"].DataAssetsSent = []string{"real-payload"}
	stubDataAssets(m, "drawio")

	_, exists := m.DataAssets["link-user-api-payload"]
	assert.False(t, exists, "should not stub a link that already carries a data asset")
}

func TestStubDataAssetsSkipsLinksNotInternetInbound(t *testing.T) {
	m := newTestModel()
	stubDataAssets(m, "drawio")

	_, exists := m.DataAssets["link-api-db-payload"]
	assert.False(t, exists, "internal (non-internet) link should not get a payload stub")
}

func TestStubDataAssetsIsDeterministicAcrossRuns(t *testing.T) {
	m1 := newTestModel()
	stubDataAssets(m1, "drawio")

	m2 := newTestModel()
	stubDataAssets(m2, "drawio")

	assert.Equal(t, len(m1.DataAssets), len(m2.DataAssets))
	for id := range m1.DataAssets {
		_, ok := m2.DataAssets[id]
		assert.True(t, ok, "expected identical stub ID %s across independent runs", id)
	}
}

func TestStubDataAssetsIsIdempotentOnReRun(t *testing.T) {
	m := newTestModel()
	stubDataAssets(m, "drawio")
	countAfterFirst := len(m.DataAssets)

	// Running again on the same (now-stubbed) model must not duplicate stubs
	// or grow DataAssetsSent/DataAssetsReceived with repeated IDs.
	stubDataAssets(m, "drawio")
	assert.Equal(t, countAfterFirst, len(m.DataAssets))

	db := m.TechnicalAssets["db"]
	count := 0
	for _, id := range db.DataAssetsStored {
		if id == "db-data" {
			count++
		}
	}
	assert.Equal(t, 1, count, "db-data should appear exactly once in DataAssetsStored")
}

func TestStubDataAssetsNilModelIsNoOp(t *testing.T) {
	stubDataAssets(nil, "drawio") // must not panic
}

func TestStubDataAssetsHandlesEmptyModel(t *testing.T) {
	m := &types.Model{
		TechnicalAssets:    map[string]*types.TechnicalAsset{},
		DataAssets:         map[string]*types.DataAsset{},
		CommunicationLinks: map[string]*types.CommunicationLink{},
	}
	stubDataAssets(m, "drawio")
	assert.Empty(t, m.DataAssets)
}
