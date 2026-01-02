package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/logmessager/client/internal/client"
)

type MainModel struct {
	users        []client.UserInfo
	selectedIdx  int
	loading      bool
	refreshTimer int
}

func NewMainModel() MainModel {
	return MainModel{
		users:       []client.UserInfo{},
		selectedIdx: 0,
	}
}

func (m MainModel) Update(msg tea.Msg, c *client.Client) (MainModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if m.selectedIdx > 0 {
				m.selectedIdx--
			}

		case "down", "j":
			if m.selectedIdx < len(m.users)-1 {
				m.selectedIdx++
			}

		case "enter":
			if len(m.users) > 0 && m.selectedIdx < len(m.users) {
				user := m.users[m.selectedIdx]
				return m, m.startChat(c, user.ID)
			}

		case "r":
			// Refresh user list
			return m, m.refreshUsers(c)

		case "l":
			// Logout
			return m, m.logout(c)
		}

	case UsersLoadedMsg:
		m.users = msg.Users
		m.loading = false
		if m.selectedIdx >= len(m.users) {
			m.selectedIdx = 0
		}

	case ChatStartedMsg:
		return m, SwitchView(ViewChat)
	}

	return m, nil
}

func (m MainModel) refreshUsers(c *client.Client) tea.Cmd {
	return func() tea.Msg {
		users, err := c.ListOnlineUsers()
		if err != nil {
			return ErrorMsg{Err: err}
		}
		return UsersLoadedMsg{Users: users}
	}
}

func (m MainModel) startChat(c *client.Client, userID string) tea.Cmd {
	return func() tea.Msg {
		requestID, err := c.RequestChat(userID)
		if err != nil {
			return ErrorMsg{Err: err}
		}
		_ = requestID
		return ChatStartedMsg{}
	}
}

func (m MainModel) logout(c *client.Client) tea.Cmd {
	return func() tea.Msg {
		if err := c.Logout(); err != nil {
			return ErrorMsg{Err: err}
		}
		return SwitchViewMsg{View: ViewLogin}
	}
}

func (m MainModel) View() string {
	var b strings.Builder

	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("86")).
		MarginBottom(1)

	headerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("241")).
		MarginBottom(1)

	userStyle := lipgloss.NewStyle().
		Padding(0, 2)

	selectedStyle := userStyle.Copy().
		Background(lipgloss.Color("57")).
		Foreground(lipgloss.Color("229"))

	onlineStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("46"))

	offlineStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("241"))

	hintStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("241")).
		MarginTop(2)

	b.WriteString(titleStyle.Render("💬 LogChat"))
	b.WriteString("\n\n")

	b.WriteString(headerStyle.Render("Online Users:"))
	b.WriteString("\n\n")

	if len(m.users) == 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("  No users online"))
	} else {
		for i, user := range m.users {
			var status string
			if user.IsOnline {
				status = onlineStyle.Render("●")
			} else {
				status = offlineStyle.Render("○")
			}

			line := fmt.Sprintf("%s %s", status, user.Username)

			if i == m.selectedIdx {
				b.WriteString(selectedStyle.Render(line))
			} else {
				b.WriteString(userStyle.Render(line))
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("\n")
	b.WriteString(hintStyle.Render("↑/↓ navigate • Enter to chat • R refresh • L logout • Ctrl+C quit"))

	return lipgloss.NewStyle().Padding(2, 4).Render(b.String())
}

// Messages

type UsersLoadedMsg struct {
	Users []client.UserInfo
}

type ChatStartedMsg struct{}
