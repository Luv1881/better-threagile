package server

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/threagile/threagile/pkg/input"
	"golang.org/x/crypto/argon2"
)

// creates a sub-folder (named by a new UUID) inside the token folder
func (s *server) createNewModel(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	ok = s.checkObjectCreationThrottler(ginContext, "MODEL")
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)

	aUuid := uuid.New().String()
	err := os.Mkdir(folderNameForModel(folderNameOfKey, aUuid), 0700)
	if err != nil {
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to create model",
		})
		return
	}

	aYaml := `title: New Threat Model
threagile_version: ` + s.config.GetThreagileVersion() + `
author:
  name: ""
  homepage: ""
date:
business_overview:
  description: ""
  images: []
technical_overview:
  description: ""
  images: []
business_criticality: ""
management_summary_comment: ""
questions: {}
abuse_cases: {}
security_requirements: {}
tags_available: []
data_assets: {}
technical_assets: {}
trust_boundaries: {}
shared_runtimes: {}
individual_risk_categories: {}
risk_tracking: {}
diagram_tweak_nodesep: ""
diagram_tweak_ranksep: ""
diagram_tweak_edge_layout: ""
diagram_tweak_suppress_edge_labels: false
diagram_tweak_invisible_connections_between_assets: []
diagram_tweak_same_rank_assets: []`

	ok = s.writeModelYAML(ginContext, aYaml, key, folderNameForModel(folderNameOfKey, aUuid), "New Model Creation", true)
	if ok {
		ginContext.JSON(http.StatusCreated, gin.H{
			"message": "model created",
			"id":      aUuid,
		})
	}
}

type payloadModels struct {
	ID                string    `yaml:"id" json:"id"`
	Title             string    `yaml:"title" json:"title"`
	TimestampCreated  time.Time `yaml:"timestamp_created" json:"timestamp_created"`
	TimestampModified time.Time `yaml:"timestamp_modified" json:"timestamp_modified"`
}

func (s *server) listModels(ginContext *gin.Context) { // TODO currently returns error when any model is no longer valid in syntax, so eventually have some fallback to not just bark on an invalid model...
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)

	result := make([]payloadModels, 0)
	modelFolders, err := os.ReadDir(folderNameOfKey)
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "token not found",
		})
		return
	}
	for _, dirEntry := range modelFolders {
		if dirEntry.IsDir() {
			modelStat, err := os.Stat(filepath.Join(folderNameOfKey, dirEntry.Name(), s.config.GetInputFile()))
			if err != nil {
				log.Println(err)
				ginContext.JSON(http.StatusNotFound, gin.H{
					"error": "unable to list model",
				})
				return
			}
			aModel, _, ok := s.readModel(ginContext, dirEntry.Name(), key, folderNameOfKey)
			if !ok {
				return
			}
			fileInfo, err := dirEntry.Info()
			if err != nil {
				log.Println(err)
				ginContext.JSON(http.StatusNotFound, gin.H{
					"error": "unable to get file info",
				})
				return
			}
			result = append(result, payloadModels{
				ID:                dirEntry.Name(),
				Title:             aModel.Title,
				TimestampCreated:  fileInfo.ModTime(),
				TimestampModified: modelStat.ModTime(),
			})
		}
	}
	ginContext.JSON(http.StatusOK, result)
}

func (s *server) deleteModel(ginContext *gin.Context) {
	folderNameOfKey, _, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	folder, ok := s.checkModelFolder(ginContext, ginContext.Param("model-id"), folderNameOfKey)
	if ok {
		if folder != filepath.Clean(folder) {
			ginContext.JSON(http.StatusInternalServerError, gin.H{
				"error": "model-id is weird",
			})
			return
		}
		err := os.RemoveAll(folder)
		if err != nil {
			ginContext.JSON(http.StatusNotFound, gin.H{
				"error": "model not found",
			})
			return
		}
		ginContext.JSON(http.StatusOK, gin.H{
			"message": "model deleted",
		})
	}
}

func (s *server) readModel(ginContext *gin.Context, modelUUID string, key []byte, folderNameOfKey string) (modelInputResult input.Model, yamlText string, ok bool) {
	modelFolder, ok := s.checkModelFolder(ginContext, modelUUID, folderNameOfKey)
	if !ok {
		return modelInputResult, yamlText, false
	}
	cryptoKey := generateKeyFromAlreadyStrongRandomInput(key)
	block, err := aes.NewCipher(cryptoKey)
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}

	fileBytes, err := os.ReadFile(filepath.Clean(filepath.Join(modelFolder, s.config.GetInputFile())))
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}

	nonce := fileBytes[0:12]
	ciphertext := fileBytes[12:]
	plaintext, err := aesGcm.Open(nil, nonce, ciphertext, nil) // #nosec G407 // false positive The nounce is read from file for decryption not encryption
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}

	r, err := gzip.NewReader(bytes.NewReader(plaintext))
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(r)
	modelInput := new(input.Model).Defaults()
	yamlBytes := buf.Bytes()
	err = yaml.Unmarshal(yamlBytes, &modelInput)
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}
	return *modelInput, string(yamlBytes), true
}

func (s *server) writeModel(ginContext *gin.Context, key []byte, folderNameOfKey string, modelInput *input.Model, changeReasonForHistory string) (ok bool) {
	modelFolder, ok := s.checkModelFolder(ginContext, ginContext.Param("model-id"), folderNameOfKey)
	if ok {
		modelInput.ThreagileVersion = s.config.GetThreagileVersion()
		yamlBytes, err := yaml.Marshal(modelInput)
		if err != nil {
			log.Println(err)
			ginContext.JSON(http.StatusInternalServerError, gin.H{
				"error": "unable to write model",
			})
			return false
		}
		/*
			yamlBytes = model.ReformatYAML(yamlBytes)
		*/
		return s.writeModelYAML(ginContext, string(yamlBytes), key, modelFolder, changeReasonForHistory, false)
	}
	return false
}

func (s *server) checkModelFolder(ginContext *gin.Context, modelUUID string, folderNameOfKey string) (modelFolder string, ok bool) {
	uuidParsed, err := uuid.Parse(modelUUID)
	if err != nil {
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "model not found",
		})
		return modelFolder, false
	}
	modelFolder = folderNameForModel(folderNameOfKey, uuidParsed.String())
	if _, err := os.Stat(modelFolder); os.IsNotExist(err) {
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "model not found",
		})
		return modelFolder, false
	}
	return modelFolder, true
}

func (s *server) getModel(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	_, yamlText, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		tmpResultFile, err := os.CreateTemp(s.config.GetTempFolder(), "threagile-*.yaml")
		if err != nil {
			handleErrorInServiceCall(err, ginContext)
			return
		}
		err = os.WriteFile(tmpResultFile.Name(), []byte(yamlText), 0400) // #nosec G703
		if err != nil {
			log.Println(err)
			ginContext.JSON(http.StatusInternalServerError, gin.H{
				"error": "unable to stream model file",
			})
			return
		}
		defer func() { _ = os.Remove(tmpResultFile.Name()) }() // #nosec G703
		ginContext.FileAttachment(tmpResultFile.Name(), s.config.GetInputFile())
	}
}

// fully replaces threagile.yaml in sub-folder given by UUID
func (s *server) importModel(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)

	aUuid := ginContext.Param("model-id") // UUID is syntactically validated in readModel+checkModelFolder (next line) via uuid.Parse(modelUUID)
	_, _, ok = s.readModel(ginContext, aUuid, key, folderNameOfKey)
	if ok {
		// first analyze it simply by executing the full risk process (just discard the result) to ensure that everything would work
		yamlContent, ok := s.execute(ginContext, true)
		if ok {
			// if we're here, then no problem was raised, so ok to proceed
			ok = s.writeModelYAML(ginContext, string(yamlContent), key, folderNameForModel(folderNameOfKey, aUuid), "Model Import", false)
			if ok {
				ginContext.JSON(http.StatusCreated, gin.H{
					"message": "model imported",
				})
			}
		}
	}
}

func (s *server) analyzeModelOnServerDirectly(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer func() {
		s.unlockFolder(folderNameOfKey)
		var err error
		if r := recover(); r != nil {
			err = r.(error)
			if s.config.GetVerbose() {
				log.Println(err)
			}
			log.Println(err)
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": strings.TrimSpace(err.Error()),
			})
			ok = false
		}
	}()

	dpi, err := strconv.Atoi(ginContext.DefaultQuery("dpi", strconv.Itoa(s.config.GetGraphvizDPI())))
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}

	_, yamlText, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if !ok {
		return
	}
	tmpModelFile, err := os.CreateTemp(s.config.GetTempFolder(), "threagile-direct-analyze-*")
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}
	defer func() { _ = os.Remove(tmpModelFile.Name()) }() // #nosec G703
	tmpOutputDir, err := os.MkdirTemp(s.config.GetTempFolder(), "threagile-direct-analyze-")
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}
	defer func() { _ = os.RemoveAll(tmpOutputDir) }()
	tmpResultFile, err := os.CreateTemp(s.config.GetTempFolder(), "threagile-result-*.zip")
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}
	defer func() { _ = os.Remove(tmpResultFile.Name()) }() // #nosec G703

	if err = os.WriteFile(tmpModelFile.Name(), []byte(yamlText), 0400); err != nil { // #nosec G703
		handleErrorInServiceCall(err, ginContext)
		return
	}
	if err = s.doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, true, true, true, true, true, true, true, true, dpi, ginContext.DefaultQuery("methodology", s.config.GetMethodology())); err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}
	err = os.WriteFile(filepath.Join(tmpOutputDir, s.config.GetInputFile()), []byte(yamlText), 0400)
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}

	files := []string{
		filepath.Join(tmpOutputDir, s.config.GetInputFile()),
		filepath.Join(tmpOutputDir, s.config.GetDataFlowDiagramFilenamePNG()),
		filepath.Join(tmpOutputDir, s.config.GetDataAssetDiagramFilenamePNG()),
		filepath.Join(tmpOutputDir, s.config.GetReportFilename()),
		filepath.Join(tmpOutputDir, s.config.GetExcelRisksFilename()),
		filepath.Join(tmpOutputDir, s.config.GetExcelTagsFilename()),
		filepath.Join(tmpOutputDir, s.config.GetJsonRisksFilename()),
		filepath.Join(tmpOutputDir, s.config.GetJsonTechnicalAssetsFilename()),
		filepath.Join(tmpOutputDir, s.config.GetJsonStatsFilename()),
	}
	if s.config.GetKeepDiagramSourceFiles() {
		files = append(files, filepath.Join(tmpOutputDir, s.config.GetDataFlowDiagramFilenameDOT()))
		files = append(files, filepath.Join(tmpOutputDir, s.config.GetDataAssetDiagramFilenameDOT()))
	}
	err = zipFiles(tmpResultFile.Name(), files)
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}
	if s.config.GetVerbose() {
		log.Println("Streaming back result file: " + tmpResultFile.Name())
	}
	ginContext.FileAttachment(tmpResultFile.Name(), "threagile-result.zip")
}

func (s *server) writeModelYAML(ginContext *gin.Context, yaml string, key []byte, modelFolder string, changeReasonForHistory string, skipBackup bool) (ok bool) {
	if s.config.GetVerbose() {
		log.Println("about to write " + strconv.Itoa(len(yaml)) + " bytes of yaml into model folder: " + modelFolder)
	}
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = w.Write([]byte(yaml))
	_ = w.Close()
	plaintext := b.Bytes()
	cryptoKey := generateKeyFromAlreadyStrongRandomInput(key)
	block, err := aes.NewCipher(cryptoKey)
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to write model",
		})
		return false
	}
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to write model",
		})
		return false
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to write model",
		})
		return false
	}
	ciphertext := aesGcm.Seal(nil, nonce, plaintext, nil) // #nosec G407 // The nounce is read from random so it shoul be random each run
	if !skipBackup {
		err = s.backupModelToHistory(modelFolder, changeReasonForHistory)
		if err != nil {
			log.Println(err)
			ginContext.JSON(http.StatusInternalServerError, gin.H{
				"error": "unable to write model",
			})
			return false
		}
	}
	f, err := os.Create(filepath.Clean(filepath.Join(modelFolder, s.config.GetInputFile())))
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to write model",
		})
		return false
	}
	_, _ = f.Write(nonce)
	_, _ = f.Write(ciphertext)
	_ = f.Close()
	return true
}

func (s *server) lockFolder(folderName string) {
	s.globalLock.Lock()
	defer s.globalLock.Unlock()
	_, exists := s.locksByFolderName[folderName]
	if !exists {
		s.locksByFolderName[folderName] = &sync.Mutex{}
	}
	s.locksByFolderName[folderName].Lock()
}

func (s *server) unlockFolder(folderName string) {
	if _, exists := s.locksByFolderName[folderName]; exists {
		s.locksByFolderName[folderName].Unlock()
		delete(s.locksByFolderName, folderName)
	}
}

func (s *server) backupModelToHistory(modelFolder string, changeReasonForHistory string) (err error) {
	// Sanitize inputs to prevent path traversal
	safeReason := filepath.Base(changeReasonForHistory)
	baseDir, resolveErr := filepath.Abs(s.config.GetDataFolder())
	if resolveErr != nil {
		return fmt.Errorf("failed to resolve data folder: %w", resolveErr)
	}
	cleanModelFolder, resolveErr := filepath.Abs(modelFolder)
	if resolveErr != nil {
		return fmt.Errorf("failed to resolve model folder: %w", resolveErr)
	}
	if !strings.HasPrefix(cleanModelFolder, baseDir) {
		return fmt.Errorf("model folder %q is outside data directory", modelFolder)
	}
	historyFolder := filepath.Join(cleanModelFolder, "history")
	if _, err := os.Stat(historyFolder); os.IsNotExist(err) {
		err = os.Mkdir(historyFolder, 0700)
		if err != nil {
			return err
		}
	}
	inputFile := filepath.Join(cleanModelFolder, filepath.Base(s.config.GetInputFile()))
	inputModel, err := os.ReadFile(filepath.Clean(inputFile))
	if err != nil {
		return err
	}
	historyFile := filepath.Join(historyFolder, time.Now().Format("2006-01-02 15:04:05")+" "+safeReason+".backup")
	err = os.WriteFile(historyFile, inputModel, 0400) // #nosec G703
	if err != nil {
		return err
	}
	// now delete any old files if over limit to keep
	files, err := os.ReadDir(filepath.Clean(historyFolder))
	if err != nil {
		return err
	}
	if len(files) > s.config.GetBackupHistoryFilesToKeep() {
		requiredToDelete := len(files) - s.config.GetBackupHistoryFilesToKeep()
		sort.Slice(files, func(i, j int) bool {
			return files[i].Name() < files[j].Name()
		})
		for _, file := range files {
			requiredToDelete--
			if file.Name() != filepath.Clean(file.Name()) {
				return fmt.Errorf("weird file name %v", file.Name())
			}
			err = os.Remove(filepath.Clean(filepath.Join(historyFolder, file.Name())))
			if err != nil {
				return err
			}
			if requiredToDelete <= 0 {
				break
			}
		}
	}
	return
}

func folderNameForModel(folderNameOfKey string, uuid string) string {
	return filepath.Join(folderNameOfKey, uuid)
}

type argon2Params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

func generateKeyFromAlreadyStrongRandomInput(alreadyRandomInput []byte) []byte {
	// Establish the parameters to use for Argon2.
	p := &argon2Params{
		memory:      64 * 1024,
		iterations:  3,
		parallelism: 2,
		saltLength:  16,
		keyLength:   keySize,
	}
	// As the input is already cryptographically secure random, the salt is simply the first n bytes
	salt := alreadyRandomInput[0:p.saltLength]
	hash := argon2.IDKey(alreadyRandomInput[p.saltLength:], salt, p.iterations, p.memory, p.parallelism, p.keyLength)
	return hash
}

func lowerCaseAndTrim(tags []string) []string {
	for i := range tags {
		tags[i] = strings.ToLower(strings.TrimSpace(tags[i]))
	}
	return tags
}
