package main

import (
	"github.com/gin-gonic/gin"
)

func index_html(c *gin.Context) {
	c.HTML(200, "index.html", gin.H{})
}

func ErrorTest_html(c *gin.Context) {
	c.HTML(200, "ErrorTest.html", gin.H{})
}

func ServerTest_html(c *gin.Context) {
	c.HTML(200, "ServerTest.html", gin.H{})
}

func HermesTest_html(c *gin.Context) {
	c.HTML(200, "HermesTest.html", gin.H{})
}

func main() {
	r := gin.Default()
	r.LoadHTMLGlob("Web/template/html/*")
	r.GET("/", index_html)
	r.GET("/ErrorTest", ErrorTest_html)
	r.GET("/ServerTest", ServerTest_html)
	r.GET("/HermesTest", HermesTest_html)
	r.GET("/api/HermesTest", doHermesTotalTest)
	doErrorTest(r)
	start_m2p(r)
	start_sc(r)
	r.Run(":8000")
}
