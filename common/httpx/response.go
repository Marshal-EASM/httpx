package httpx

import (
	"github.com/PuerkitoBio/goquery"
	"net/url"
	"strings"
	"time"

	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	httputil "github.com/projectdiscovery/utils/http"
)

// Response contains the response to a server
type Response struct {
	StatusCode    int
	Headers       map[string][]string
	RawData       []byte // undecoded data
	Data          []byte // decoded data
	ContentLength int
	Raw           string
	RawHeaders    string
	Words         int
	Lines         int
	TLSData       *clients.Response
	CSPData       *CSPData
	HTTP2         bool
	Pipeline      bool
	Duration      time.Duration
	Chain         []httputil.ChainItem
}

// ChainItem request=>response
type ChainItem struct {
	Request    string `json:"request,omitempty"`
	Response   string `json:"response,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	Location   string `json:"location,omitempty"`
	RequestURL string `json:"request-url,omitempty"`
}

// GetHeader value
func (r *Response) GetHeader(name string) string {
	v, ok := r.Headers[name]
	if ok {
		return strings.Join(v, " ")
	}

	return ""
}

// GetHeaderPart with offset
func (r *Response) GetHeaderPart(name, sep string) string {
	v, ok := r.Headers[name]
	if ok && len(v) > 0 {
		tokens := strings.Split(strings.Join(v, " "), sep)
		return tokens[0]
	}

	return ""
}

// GetChainStatusCodes from redirects
func (r *Response) GetChainStatusCodes() []int {
	var statusCodes []int
	for _, chainItem := range r.Chain {
		statusCodes = append(statusCodes, chainItem.StatusCode)
	}
	return statusCodes
}

// GetChain dump the whole redirect chain as string
func (r *Response) GetChain() string {
	var respchain strings.Builder
	for _, chainItem := range r.Chain {
		respchain.Write(chainItem.Request)
		respchain.Write(chainItem.Response)
	}
	return respchain.String()
}

// GetChainAsSlice dump the whole redirect chain as structuerd slice
func (r *Response) GetChainAsSlice() (chain []ChainItem) {
	for _, chainItem := range r.Chain {
		chain = append(chain, ChainItem{
			Request:    string(chainItem.Request),
			Response:   string(chainItem.Response),
			StatusCode: chainItem.StatusCode,
			Location:   chainItem.Location,
			RequestURL: chainItem.RequestURL,
		})
	}
	return
}

// HasChain redirects
func (r *Response) HasChain() bool {
	return len(r.Chain) > 1
}

// GetChainLastURL returns the final URL
func (r *Response) GetChainLastURL() string {
	if r.HasChain() {
		lastitem := r.Chain[len(r.Chain)-1]
		return lastitem.RequestURL
	}
	return ""
}
func (r *Response) ExtractJSLink(inputUrl string) (jsLinks []string, err error) {
	baseURL, _ := url.Parse(inputUrl)
	// 读取响应数据
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(r.Raw))
	if err != nil {
		return jsLinks, err
	}
	// 获取所有的script标签
	doc.Find("script[src]").Each(func(i int, s *goquery.Selection) {
		link, exist := s.Attr("src")
		if exist && strings.HasSuffix(link, ".js") {
			absLink := toAbsURL(baseURL, link)
			jsLinks = append(jsLinks, absLink)
		}
	})
	return jsLinks, nil
}
func toAbsURL(baseURL *url.URL, link string) string {
	u, err := url.Parse(link)
	if err != nil {
		return ""
	}
	if u.IsAbs() {
		return u.String()
	}
	return baseURL.ResolveReference(u).String()
}
