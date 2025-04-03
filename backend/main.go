package main

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// SnortRule struct to store user inputs
type SnortRule struct {
	AlertType           string `json:"alertType"`
	Protocol            string `json:"protocol"`
	SrcIP               string `json:"srcIP"`
	SrcPort             string `json:"srcPort"`
	DstIP               string `json:"dstIP"`
	DstPort             string `json:"dstPort"`
	Direction           string `json:"direction"`
	Message             string `json:"message"`
	Sid                 string `json:"sid"`
	Priority            string `json:"priority"`
	Flow                string `json:"flow"`
	Flags               string `json:"flags"`
	Content             string `json:"content"`
	Nocase              bool   `json:"nocase"`
	HTTPMethod          string `json:"http_method"`
	HTTPURI             bool   `json:"http_uri"`
	HTTPHeader          string `json:"http_header"`
	DNSQuery            string `json:"dns_query"`
	Dsize               string `json:"dsize"`
	Threshold           string `json:"threshold"`
	Reference           string `json:"reference"`
	Classtype           string `json:"classtype"`
	Pcre                string `json:"pcre"`
	PcreCaseInsensitive bool   `json:"pcreCaseInsensitive"`
}

var options []string

func validateRule(rule SnortRule) string {
	if rule.AlertType == "" || rule.Protocol == "" || rule.SrcIP == "" || rule.DstIP == "" || rule.Sid == "" {
		return "All required fields must be filled."
	}
	if _, err := strconv.Atoi(rule.Sid); err != nil || rule.Sid == "0" {
		return "SID must be a valid number greater than 0."
	}
	if rule.Pcre != "" {
		pcreOption := fmt.Sprintf(`pcre:"%s"`, rule.Pcre)
		if rule.PcreCaseInsensitive {
			// Ensure case insensitivity is added to regex
			if !strings.HasSuffix(rule.Pcre, "i") {
				pcreOption = fmt.Sprintf(`pcre:"%si"`, strings.TrimSuffix(rule.Pcre, "/"))
			}
		}
		options = append(options, pcreOption)
	}
	return ""
}

// Generate Snort Rule
func generateRule(c *gin.Context) {
	var rule SnortRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate Rule Before Processing
	validationError := validateRule(rule)
	if validationError != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": validationError})
		return
	}

	// Required options
	options = append(options, fmt.Sprintf(`msg:"%s"`, rule.Message))
	options = append(options, fmt.Sprintf(`sid:%s`, rule.Sid))
	options = append(options, fmt.Sprintf(`priority:%s`, rule.Priority))

	// Optional fields
	if rule.Flow != "" {
		options = append(options, fmt.Sprintf("flow:%s", rule.Flow))
	}
	if rule.Flags != "" {
		options = append(options, fmt.Sprintf("flags:%s", rule.Flags))
	}
	if rule.Content != "" {
		contentOption := fmt.Sprintf(`content:"%s"`, rule.Content)
		if rule.Nocase {
			contentOption += "; nocase"
		}
		options = append(options, contentOption)
	}
	if rule.HTTPURI {
		options = append(options, "http_uri")
	}
	if rule.HTTPMethod != "" {
		options = append(options, fmt.Sprintf(`http_method:"%s"`, rule.HTTPMethod))
	}
	if rule.HTTPHeader != "" {
		options = append(options, fmt.Sprintf(`http_header:"%s"`, rule.HTTPHeader))
	}
	if rule.DNSQuery != "" {
		options = append(options, fmt.Sprintf(`dns_query:"%s"`, rule.DNSQuery))
	}
	if rule.Dsize != "" {
		options = append(options, fmt.Sprintf("dsize:%s", rule.Dsize))
	}
	if rule.Threshold != "" {
		options = append(options, fmt.Sprintf("threshold:%s", rule.Threshold))
	}
	if rule.Reference != "" {
		options = append(options, fmt.Sprintf("reference:%s", rule.Reference))
	}
	if rule.Classtype != "" {
		options = append(options, fmt.Sprintf("classtype:%s", rule.Classtype))
	}
	if rule.Pcre != "" {
		options = append(options, fmt.Sprintf(`pcre:"%s";`, rule.Pcre))
	}

	// Build final rule string
	ruleStr := fmt.Sprintf(
		`%s %s %s %s %s %s %s (%s)`,
		rule.AlertType, rule.Protocol, rule.SrcIP, rule.SrcPort,
		rule.Direction, rule.DstIP, rule.DstPort,
		strings.Join(options, "; "),
	)

	fmt.Println("🚀 Generated Snort Rule:", ruleStr)

	c.JSON(http.StatusOK, gin.H{"rule": ruleStr})
}

func main() {
	r := gin.Default()

	r.Use(cors.Default())

	r.POST("/generate-rule", generateRule)

	r.Run(":8080")
}
