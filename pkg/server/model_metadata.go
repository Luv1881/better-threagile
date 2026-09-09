package server

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/types"
)

type payloadCover struct {
	Title  string       `yaml:"title" json:"title"`
	Date   time.Time    `yaml:"date" json:"date"`
	Author input.Author `yaml:"author" json:"author"`
}

func (s *server) setCover(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadCover{}
		err := ginContext.BindJSON(&payload)
		if err != nil {
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		modelInput.Title = payload.Title
		if !payload.Date.IsZero() {
			modelInput.Date = payload.Date.Format("2006-01-02")
		}
		modelInput.Author.Name = payload.Author.Name
		modelInput.Author.Homepage = payload.Author.Homepage
		ok = s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Cover Update")
		if ok {
			ginContext.JSON(http.StatusOK, gin.H{
				"message": "model updated",
			})
		}
	}
}

func (s *server) getCover(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	aModel, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		ginContext.JSON(http.StatusOK, gin.H{
			"title":  aModel.Title,
			"date":   aModel.Date,
			"author": aModel.Author,
		})
	}
}

type payloadOverview struct {
	ManagementSummaryComment string         `yaml:"management_summary_comment" json:"management_summary_comment"`
	BusinessCriticality      string         `yaml:"business_criticality" json:"business_criticality"`
	BusinessOverview         input.Overview `yaml:"business_overview" json:"business_overview"`
	TechnicalOverview        input.Overview `yaml:"technical_overview" json:"technical_overview"`
}

func (s *server) setOverview(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadOverview{}
		err := ginContext.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		criticality, err := types.ParseCriticality(payload.BusinessCriticality)
		if err != nil {
			handleErrorInServiceCall(err, ginContext)
			return
		}
		modelInput.ManagementSummaryComment = payload.ManagementSummaryComment
		modelInput.BusinessCriticality = criticality.String()
		modelInput.BusinessOverview.Description = payload.BusinessOverview.Description
		modelInput.BusinessOverview.Images = payload.BusinessOverview.Images
		modelInput.TechnicalOverview.Description = payload.TechnicalOverview.Description
		modelInput.TechnicalOverview.Images = payload.TechnicalOverview.Images
		ok = s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Overview Update")
		if ok {
			ginContext.JSON(http.StatusOK, gin.H{
				"message": "model updated",
			})
		}
	}
}

func (s *server) getOverview(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	aModel, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		ginContext.JSON(http.StatusOK, gin.H{
			"management_summary_comment": aModel.ManagementSummaryComment,
			"business_criticality":       aModel.BusinessCriticality,
			"business_overview":          aModel.BusinessOverview,
			"technical_overview":         aModel.TechnicalOverview,
		})
	}
}

type payloadAbuseCases map[string]string

func (s *server) setAbuseCases(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadAbuseCases{}
		err := ginContext.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		modelInput.AbuseCases = payload
		ok = s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Abuse Cases Update")
		if ok {
			ginContext.JSON(http.StatusOK, gin.H{
				"message": "model updated",
			})
		}
	}
}

func (s *server) getAbuseCases(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	aModel, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		ginContext.JSON(http.StatusOK, aModel.AbuseCases)
	}
}

type payloadSecurityRequirements map[string]string

func (s *server) setSecurityRequirements(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadSecurityRequirements{}
		err := ginContext.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		modelInput.SecurityRequirements = payload
		ok = s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Security Requirements Update")
		if ok {
			ginContext.JSON(http.StatusOK, gin.H{
				"message": "model updated",
			})
		}
	}
}

func (s *server) getSecurityRequirements(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	aModel, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		ginContext.JSON(http.StatusOK, aModel.SecurityRequirements)
	}
}
