package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/logmessager/client/internal/client"
)

type LoginModel struct {
	usernameInput textinput.Model
	passwordInput textinput.Model
	focusIndex    int
}

func NewLoginModel() LoginModel {
	usernameInput := textinput.New()
	usernameInput.Placeholder = "Username"
	usernameInput.Focus()
	usernameInput.CharLimit = 50
	usernameInput.Width = 30

	passwordInput := textinput.New()
	passwordInput.Placeholder = "Password"
	passwordInput.EchoMode = textinput.EchoPassword
	passwordInput.EchoCharacter = '•'
	passwordInput.CharLimit = 100
	passwordInput.Width = 30

	return LoginModel{
		usernameInput: usernameInput,
		passwordInput: passwordInput,
		focusIndex:    0,
	}
}

func (m LoginModel) Update(msg tea.Msg, c *client.Client) (LoginModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "tab", "shift+tab", "down", "up":
			// Cycle focus
			if msg.String() == "up" || msg.String() == "shift+tab" {
				m.focusIndex--
			} else {
				m.focusIndex++
			}

			if m.focusIndex > 2 {
				m.focusIndex = 0
			} else if m.focusIndex < 0 {
				m.focusIndex = 2
			}

			cmds := make([]tea.Cmd, 2)
			if m.focusIndex == 0 {
				cmds[0] = m.usernameInput.Focus()
				m.passwordInput.Blur()
			} else if m.focusIndex == 1 {
				m.usernameInput.Blur()
				cmds[1] = m.passwordInput.Focus()
			} else {
				m.usernameInput.Blur()
				m.passwordInput.Blur()
			}

			return m, tea.Batch(cmds...)

		case "enter":
			if m.focusIndex == 2 {
				// Login button
				return m, m.doLogin(c)
			} else if m.focusIndex < 2 {
				// Move to next field
				m.focusIndex++
				if m.focusIndex == 1 {
					m.usernameInput.Blur()
					return m, m.passwordInput.Focus()
				} else if m.focusIndex == 2 {
					m.passwordInput.Blur()
				}
			}

		case "ctrl+r":
			// Switch to register
			return m, SwitchView(ViewRegister)
		}
	}

	// Update inputs
	var cmd tea.Cmd
	if m.focusIndex == 0 {
		m.usernameInput, cmd = m.usernameInput.Update(msg)
	} else if m.focusIndex == 1 {
		m.passwordInput, cmd = m.passwordInput.Update(msg)
	}

	return m, cmd
}

func (m LoginModel) doLogin(c *client.Client) tea.Cmd {
	username := strings.TrimSpace(m.usernameInput.Value())
	password := m.passwordInput.Value()

	if username == "" || password == "" {
		return ShowError(fmt.Errorf("username and password required"))
	}

	return func() tea.Msg {
		if err := c.Login(username, password); err != nil {
			return ErrorMsg{Err: err}
		}
		return SwitchViewMsg{View: ViewMain}
	}
}

func (m LoginModel) View() string {
	var b strings.Builder

	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("86")).
		MarginBottom(1)

	inputStyle := lipgloss.NewStyle().
		MarginBottom(1)

	buttonStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Padding(0, 2).
		MarginTop(1)

	buttonFocusedStyle := buttonStyle.
		Background(lipgloss.Color("86"))

	hintStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("241")).
		MarginTop(2)

	b.WriteString(titleStyle.Render("🔐 LogChat - Login"))
	b.WriteString("\n\n")

	b.WriteString(inputStyle.Render(m.usernameInput.View()))
	b.WriteString("\n")
	b.WriteString(inputStyle.Render(m.passwordInput.View()))
	b.WriteString("\n\n")

	// Login button
	if m.focusIndex == 2 {
		b.WriteString(buttonFocusedStyle.Render("[ Login ]"))
	} else {
		b.WriteString(buttonStyle.Render("[ Login ]"))
	}

	b.WriteString("\n")
	b.WriteString(hintStyle.Render("Press Ctrl+R to register • Ctrl+C to quit"))

	return lipgloss.NewStyle().Padding(2, 4).Render(b.String())
}
