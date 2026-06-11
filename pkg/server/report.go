/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package server

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

type responseType int

const (
	dataFlowDiagram responseType = iota
	dataAssetDiagram
	reportPDF
	risksExcel
	tagsExcel
	risksJSON
	technicalAssetsJSON
	statsJSON
)

func (s *server) streamDataFlowDiagram(ginContext *gin.Context) {
	s.streamResponse(ginContext, dataFlowDiagram)
}

func (s *server) streamDataAssetDiagram(ginContext *gin.Context) {
	s.streamResponse(ginContext, dataAssetDiagram)
}

func (s *server) streamReportPDF(ginContext *gin.Context) {
	s.streamResponse(ginContext, reportPDF)
}

func (s *server) streamRisksExcel(ginContext *gin.Context) {
	s.streamResponse(ginContext, risksExcel)
}

func (s *server) streamTagsExcel(ginContext *gin.Context) {
	s.streamResponse(ginContext, tagsExcel)
}

func (s *server) streamRisksJSON(ginContext *gin.Context) {
	s.streamResponse(ginContext, risksJSON)
}

func (s *server) streamTechnicalAssetsJSON(ginContext *gin.Context) {
	s.streamResponse(ginContext, technicalAssetsJSON)
}

func (s *server) streamStatsJSON(ginContext *gin.Context) {
	s.streamResponse(ginContext, statsJSON)
}

func (s *server) streamResponse(ginContext *gin.Context, responseType responseType) {
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
	tmpModelFile, err := os.CreateTemp(s.config.GetTempFolder(), "threagile-render-*")
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}
	defer func() { _ = os.Remove(tmpModelFile.Name()) }()
	tmpOutputDir, err := os.MkdirTemp(s.config.GetTempFolder(), "threagile-render-")
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}
	defer func() { _ = os.RemoveAll(tmpOutputDir) }()
	if err = os.WriteFile(tmpModelFile.Name(), []byte(yamlText), 0400); err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}
	methodology := ginContext.DefaultQuery("methodology", s.config.GetMethodology())
	switch responseType {
	case dataFlowDiagram:
		if err = s.doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, true, false, false, false, false, false, false, false, dpi, methodology); err != nil {
			handleErrorInServiceCall(err, ginContext)
			return
		}
		ginContext.File(filepath.Clean(filepath.Join(tmpOutputDir, s.config.GetDataFlowDiagramFilenamePNG())))

	case dataAssetDiagram:
		if err = s.doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, false, true, false, false, false, false, false, false, dpi, methodology); err != nil {
			handleErrorInServiceCall(err, ginContext)
			return
		}
		ginContext.File(filepath.Clean(filepath.Join(tmpOutputDir, s.config.GetDataAssetDiagramFilenamePNG())))

	case reportPDF:
		if err = s.doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, false, false, true, false, false, false, false, false, dpi, methodology); err != nil {
			handleErrorInServiceCall(err, ginContext)
			return
		}
		ginContext.FileAttachment(filepath.Clean(filepath.Join(tmpOutputDir, s.config.GetReportFilename())), s.config.GetReportFilename())

	case risksExcel:
		if err = s.doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, false, false, false, true, false, false, false, false, dpi, methodology); err != nil {
			handleErrorInServiceCall(err, ginContext)
			return
		}
		ginContext.FileAttachment(filepath.Clean(filepath.Join(tmpOutputDir, s.config.GetExcelRisksFilename())), s.config.GetExcelRisksFilename())

	case tagsExcel:
		if err = s.doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, false, false, false, false, true, false, false, false, dpi, methodology); err != nil {
			handleErrorInServiceCall(err, ginContext)
			return
		}
		ginContext.FileAttachment(filepath.Clean(filepath.Join(tmpOutputDir, s.config.GetExcelTagsFilename())), s.config.GetExcelTagsFilename())

	case risksJSON:
		if err = s.doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, false, false, false, false, false, true, false, false, dpi, methodology); err != nil {
			handleErrorInServiceCall(err, ginContext)
			return
		}
		jsonData, err := os.ReadFile(filepath.Clean(filepath.Join(tmpOutputDir, s.config.GetJsonRisksFilename())))
		if err != nil {
			handleErrorInServiceCall(err, ginContext)
			return
		}
		ginContext.Data(http.StatusOK, "application/json", jsonData)

	case technicalAssetsJSON:
		if err = s.doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, false, false, false, false, false, true, true, false, dpi, methodology); err != nil {
			handleErrorInServiceCall(err, ginContext)
			return
		}
		jsonData, err := os.ReadFile(filepath.Clean(filepath.Join(tmpOutputDir, s.config.GetJsonTechnicalAssetsFilename())))
		if err != nil {
			handleErrorInServiceCall(err, ginContext)
			return
		}
		ginContext.Data(http.StatusOK, "application/json", jsonData)

	case statsJSON:
		if err = s.doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, false, false, false, false, false, false, false, true, dpi, methodology); err != nil {
			handleErrorInServiceCall(err, ginContext)
			return
		}
		jsonData, err := os.ReadFile(filepath.Clean(filepath.Join(tmpOutputDir, s.config.GetJsonStatsFilename())))
		if err != nil {
			handleErrorInServiceCall(err, ginContext)
			return
		}
		ginContext.Data(http.StatusOK, "application/json", jsonData)
	}
}
