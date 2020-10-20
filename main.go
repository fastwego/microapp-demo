// Copyright 2020 FastWeGo
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fastwego/microapp/apis/subscribe_notification"

	"github.com/fastwego/microapp/apis/template_message"

	"github.com/fastwego/microapp/apis/qrcode"

	"github.com/fastwego/microapp/apis/data_caching"

	"github.com/fastwego/microapp/apis/content_security"

	"github.com/fastwego/microapp"
	"github.com/fastwego/microapp/apis/auth"

	"github.com/spf13/viper"

	"github.com/gin-gonic/gin"
)

func init() {
	// 加载配置文件
	viper.SetConfigFile(".env")
	_ = viper.ReadInConfig()

}
func main() {

	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())

	app := microapp.New(microapp.Config{
		AppId:     viper.GetString("APPID"),
		AppSecret: viper.GetString("SECRET"),
	})

	// 接口演示
	router.GET("/microapp/code2session", func(c *gin.Context) {
		params := url.Values{}
		params.Add("code", "CODE")
		resp, err := auth.Code2Session(app, params)
		fmt.Println(string(resp), err)

		c.Writer.Write(resp)
	})

	router.GET("/microapp/content_security", func(c *gin.Context) {
		payload := []byte(`{
		  "tasks": [
			{
			  "content": "要检测的文本/赌博/涩情"
			}
		  ]
		}`)
		resp, err := content_security.TextAntiDirty(app, payload)
		fmt.Println(string(resp), err)

		c.Writer.Write(resp)

		payload = []byte(`{
		  "targets": ["ad", "porn", "politics", "disgusting"],
		  "tasks": [
			{
			  "image": "https://s3.pstatp.com/toutiao/resource/developer_ssr/img/user-arrive-1@3x.86a3dc7.png"
			}
		  ]
		}`)
		resp, err = content_security.Image(app, payload)
		fmt.Println(string(resp), err)

		c.Writer.Write(resp)
	})

	router.GET("/microapp/data_caching", func(c *gin.Context) {
		payload := []byte(`{
		  "kv_list": [
			{
			  "key": "test",
			  "value": "{\"ttgame\":{\"score\":1}}"
			}
		  ]
		}`)

		var session_key []byte

		h := hmac.New(sha256.New, session_key)
		h.Write(payload)
		signature := hex.EncodeToString(h.Sum(nil))

		access_token, err := app.GetAccessTokenHandler(app)
		if err != nil {
			return
		}
		params := url.Values{}
		params.Add("access_token", access_token)
		params.Add("openid", c.Query("openid"))
		params.Add("signature", signature)
		params.Add("sig_method", "hmac_sha256")
		resp, err := data_caching.SetUserStorage(app, payload, params)
		fmt.Println(string(resp), err)

		c.Writer.Write(resp)

	})

	router.GET("/microapp/qrcode", func(c *gin.Context) {
		access_token, err := app.GetAccessTokenHandler(app)
		if err != nil {
			return
		}
		payload := []byte(`{
		  "access_token": "` + access_token + `"
		}`)

		fmt.Println(string(payload))

		resp, err := qrcode.CreateQRCode(app, payload)
		fmt.Println(string(resp), err)

		c.Writer.Write(resp)

	})

	router.GET("/microapp/template_message", func(c *gin.Context) {
		access_token, err := app.GetAccessTokenHandler(app)
		if err != nil {
			return
		}
		payload := []byte(`{
		  "access_token": "` + access_token + `",
		  "app_id": "YOUR_APP_ID",
		  "data": {
			"keyword1": {
			  "value": "v1"
			},
			"keyword2": {
			  "value": "v2"
			}
		  },
		  "page": "pages/index",
		  "form_id": "YOUR_FORM_ID",
		  "touser": "USER_OPEN_ID",
		  "template_id": "YOUR_TPL_ID"
		}`)

		fmt.Println(string(payload))
		resp, err := template_message.Send(app, payload)
		fmt.Println(string(resp), err)

		c.Writer.Write(resp)

	})

	router.GET("/microapp/subscribe_notification", func(c *gin.Context) {
		access_token, err := app.GetAccessTokenHandler(app)
		if err != nil {
			return
		}
		payload := []byte(`{
		  "access_token": "` + access_token + `",
		  "app_id": "31198cf00b********",
		  "tpl_id": "MSG38489d04608c5f0fdeb565fc5114afff6410*******",
		  "open_id": "36d4bd3c8****",
		  "data": {
			"版本号": "v1.0",
			"版本描述": "新版本发布了"
		  },
		  "page": "pages/index?a=b"
		}`)

		fmt.Println(string(payload))
		resp, err := subscribe_notification.Notify(app, payload)
		fmt.Println(string(resp), err)

		c.Writer.Write(resp)

	})

	svr := &http.Server{
		Addr:    viper.GetString("LISTEN"),
		Handler: router,
	}

	go func() {
		err := svr.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Fatalln(err)
		}
	}()

	quit := make(chan os.Signal)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	timeout := time.Duration(5) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := svr.Shutdown(ctx); err != nil {
		log.Fatalln(err)
	}
}
