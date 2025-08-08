package main

import (
	"jwtredis/config"
	"jwtredis/database"
	"jwtredis/handlers"
	"jwtredis/middleware"
	"jwtredis/models"
	"log"

	"github.com/gin-gonic/gin"
)

func main() {
	// 初始化配置
	config.InitConfig()
	
	// 初始化数据库
	database.InitDB()
	
	// 自动迁移数据库表
	database.DB.AutoMigrate(&models.User{})
	
	// 初始化Redis
	database.InitRedis()
	
	// 创建Gin实例
	r := gin.Default()
	
	// 添加CORS中间件
	r.Use(middleware.CORS())
	
	// 静态文件服务
	r.Static("/static", "./static")
	r.LoadHTMLGlob("static/*.html")
	
	// 根路径重定向到登录页面
	r.GET("/", func(c *gin.Context) {
		c.HTML(200, "index.html", nil)
	})
	
	// 公开路由
	public := r.Group("/api")
	{
		public.POST("/register", handlers.Register)
		public.POST("/login", handlers.Login)
	}
	
	// 需要认证的路由
	protected := r.Group("/api")
	protected.Use(middleware.AuthMiddleware())
	{
		protected.GET("/profile", handlers.GetProfile)
		protected.POST("/logout", handlers.Logout)
		protected.PUT("/profile", handlers.UpdateProfile)
	}
	
	// 启动服务器
	log.Println("服务器启动在端口 :8080")
	r.Run(":8080")
}
