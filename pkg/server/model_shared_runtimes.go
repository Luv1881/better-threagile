/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package server

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/threagile/threagile/pkg/input"
)

func (s *server) getTrustBoundaries(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	aModel, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		ginContext.JSON(http.StatusOK, aModel.TrustBoundaries)
	}
}

type payloadSharedRuntime struct {
	Title                  string   `yaml:"title" json:"title"`
	Id                     string   `yaml:"id" json:"id"`
	Description            string   `yaml:"description" json:"description"`
	Tags                   []string `yaml:"tags" json:"tags"`
	TechnicalAssetsRunning []string `yaml:"technical_assets_running" json:"technical_assets_running"`
}

func (s *server) setSharedRuntime(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, sharedRuntime := range modelInput.SharedRuntimes {
			if sharedRuntime.ID == ginContext.Param("shared-runtime-id") {
				payload := payloadSharedRuntime{}
				err := ginContext.BindJSON(&payload)
				if err != nil {
					log.Println(err)
					ginContext.JSON(http.StatusBadRequest, gin.H{
						"error": "unable to parse request payload",
					})
					return
				}
				sharedRuntimeInput, ok := populateSharedRuntime(ginContext, payload)
				if !ok {
					return
				}
				// in order to also update the title, remove the shared runtime from the map and re-insert it (with new key)
				delete(modelInput.SharedRuntimes, title)
				modelInput.SharedRuntimes[payload.Title] = sharedRuntimeInput
				idChanged := sharedRuntimeInput.ID != sharedRuntime.ID
				if idChanged { // ID-CHANGE-PROPAGATION
					for _, individualRiskCat := range modelInput.CustomRiskCategories {
						if individualRiskCat.RisksIdentified != nil {
							for individualRiskInstanceTitle, individualRiskInstance := range individualRiskCat.RisksIdentified {
								if individualRiskInstance.MostRelevantSharedRuntime == sharedRuntime.ID { // apply the ID change
									x := individualRiskCat.RisksIdentified[individualRiskInstanceTitle]
									x.MostRelevantSharedRuntime = sharedRuntimeInput.ID // TODO needs more testing
									individualRiskCat.RisksIdentified[individualRiskInstanceTitle] = x
								}
							}
						}
					}
				}
				ok = s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Shared Runtime Update")
				if ok {
					ginContext.JSON(http.StatusOK, gin.H{
						"message":    "shared runtime updated",
						"id":         sharedRuntimeInput.ID,
						"id_changed": idChanged, // in order to signal to clients, that other model parts might've received updates as well and should be reloaded
					})
				}
				return
			}
		}
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "shared runtime not found",
		})
	}
}

func (s *server) getSharedRuntime(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, sharedRuntime := range modelInput.SharedRuntimes {
			if sharedRuntime.ID == ginContext.Param("shared-runtime-id") {
				ginContext.JSON(http.StatusOK, gin.H{
					title: sharedRuntime,
				})
				return
			}
		}
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "shared runtime not found",
		})
	}
}

func (s *server) createNewSharedRuntime(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadSharedRuntime{}
		err := ginContext.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		if _, exists := modelInput.SharedRuntimes[payload.Title]; exists {
			ginContext.JSON(http.StatusConflict, gin.H{
				"error": "shared runtime with this title already exists",
			})
			return
		}
		// but later it will in memory keyed by its "id", so do this uniqueness check also
		for _, sharedRuntime := range modelInput.SharedRuntimes {
			if sharedRuntime.ID == payload.Id {
				ginContext.JSON(http.StatusConflict, gin.H{
					"error": "shared runtime with this id already exists",
				})
				return
			}
		}
		if !checkTechnicalAssetsExisting(modelInput, payload.TechnicalAssetsRunning) {
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": "referenced technical asset does not exist",
			})
			return
		}
		sharedRuntimeInput, ok := populateSharedRuntime(ginContext, payload)
		if !ok {
			return
		}
		if modelInput.SharedRuntimes == nil {
			modelInput.SharedRuntimes = make(map[string]input.SharedRuntime)
		}
		modelInput.SharedRuntimes[payload.Title] = sharedRuntimeInput
		ok = s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Shared Runtime Creation")
		if ok {
			ginContext.JSON(http.StatusOK, gin.H{
				"message": "shared runtime created",
				"id":      sharedRuntimeInput.ID,
			})
		}
	}
}

func checkTechnicalAssetsExisting(modelInput input.Model, techAssetIDs []string) (ok bool) {
	for _, techAssetID := range techAssetIDs {
		exists := false
		for _, val := range modelInput.TechnicalAssets {
			if val.ID == techAssetID {
				exists = true
				break
			}
		}
		if !exists {
			return false
		}
	}
	return true
}

func populateSharedRuntime(_ *gin.Context, payload payloadSharedRuntime) (sharedRuntimeInput input.SharedRuntime, ok bool) {
	sharedRuntimeInput = input.SharedRuntime{
		ID:                     payload.Id,
		Description:            payload.Description,
		Tags:                   lowerCaseAndTrim(payload.Tags),
		TechnicalAssetsRunning: payload.TechnicalAssetsRunning,
	}
	return sharedRuntimeInput, true
}

func (s *server) deleteSharedRuntime(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		referencesDeleted := false
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, sharedRuntime := range modelInput.SharedRuntimes {
			if sharedRuntime.ID == ginContext.Param("shared-runtime-id") {
				// also remove all usages of this shared runtime !!
				for _, individualRiskCat := range modelInput.CustomRiskCategories {
					if individualRiskCat.RisksIdentified != nil {
						for individualRiskInstanceTitle, individualRiskInstance := range individualRiskCat.RisksIdentified {
							if individualRiskInstance.MostRelevantSharedRuntime == sharedRuntime.ID { // apply the removal
								referencesDeleted = true
								x := individualRiskCat.RisksIdentified[individualRiskInstanceTitle]
								x.MostRelevantSharedRuntime = "" // TODO needs more testing
								individualRiskCat.RisksIdentified[individualRiskInstanceTitle] = x
							}
						}
					}
				}
				// remove it itself
				delete(modelInput.SharedRuntimes, title)
				ok = s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Shared Runtime Deletion")
				if ok {
					ginContext.JSON(http.StatusOK, gin.H{
						"message":            "shared runtime deleted",
						"id":                 sharedRuntime.ID,
						"references_deleted": referencesDeleted, // in order to signal to clients, that other model parts might've been deleted as well
					})
				}
				return
			}
		}
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "shared runtime not found",
		})
	}
}

func (s *server) getSharedRuntimes(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	aModel, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		ginContext.JSON(http.StatusOK, aModel.SharedRuntimes)
	}
}
