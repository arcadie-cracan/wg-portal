package ui

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (h *handler) handleAdminUserIndexGet() gin.HandlerFunc {
	return func(c *gin.Context) {
		currentSession := h.session.GetData(c)
		users, err := h.backend.GetAllUsers()
		if err != nil {
			// TODO
		}

		c.HTML(http.StatusOK, "admin_user_index.gohtml", gin.H{
			"Route":   c.Request.URL.Path,
			"Alerts":  h.session.GetFlashes(c),
			"Session": currentSession,
			"Static":  h.getStaticData(),
			"Users":   users,
		})
	}
}