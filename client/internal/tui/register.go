package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/logmessager/client/internal/client"
)

type RegisterModel struct {
	usernameInput        textinput.Model
	passwordInput        textinput.Model
	confirmPasswordInput textinput.Model
	focusIndex           int
}

func NewRegisterModel() RegisterModel {
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

	confirmPasswordInput := textinput.New()
	confirmPasswordInput.Placeholder = "Confirm Password"
	confirmPasswordInput.EchoMode = textinput.EchoPassword
	confirmPasswordInput.EchoCharacter = '•'
	confirmPasswordInput.CharLimit = 100
	confirmPasswordInput.Width = 30

	return RegisterModel{
		usernameInput:        usernameInput,
		passwordInput:        passwordInput,
		confirmPasswordInput: confirmPasswordInput,
		focusIndex:           0,
	}
}

func (m RegisterModel) Update(msg tea.Msg, c *client.Client) (RegisterModel, tea.Cmd) {
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

			if m.focusIndex > 3 {
				m.focusIndex = 0
			} else if m.focusIndex < 0 {
				m.focusIndex = 3
			}

			m.usernameInput.Blur()
			m.passwordInput.Blur()
			m.confirmPasswordInput.Blur()

			var cmd tea.Cmd
			switch m.focusIndex {
			case 0:
				cmd = m.usernameInput.Focus()
			case 1:
				cmd = m.passwordInput.Focus()
			case 2:
				cmd = m.confirmPasswordInput.Focus()
			}

			return m, cmd

		case "enter":
			if m.focusIndex == 3 {
				// Register button
				return m, m.doRegister(c)
			} else if m.focusIndex < 3 {
				// Move to next field
				m.focusIndex++
				m.usernameInput.Blur()
				m.passwordInput.Blur()
				m.confirmPasswordInput.Blur()

				var cmd tea.Cmd
				switch m.focusIndex {
				case 1:
					cmd = m.passwordInput.Focus()
				case 2:
					cmd = m.confirmPasswordInput.Focus()
				}
				return m, cmd
			}

		case "ctrl+l":
			// Switch to login
			return m, SwitchView(ViewLogin)
		}
	}

	// Update inputs
	var cmd tea.Cmd
	switch m.focusIndex {
	case 0:
		m.usernameInput, cmd = m.usernameInput.Update(msg)
	case 1:
		m.passwordInput, cmd = m.passwordInput.Update(msg)
	case 2:
		m.confirmPasswordInput, cmd = m.confirmPasswordInput.Update(msg)
	}

	return m, cmd
}

func (m RegisterModel) doRegister(c *client.Client) tea.Cmd {
	username := strings.TrimSpace(m.usernameInput.Value())
	password := m.passwordInput.Value()
	confirmPassword := m.confirmPasswordInput.Value()

	if username == "" || password == "" {
		return ShowError(fmt.Errorf("username and password required"))
	}

	if len(username) < 3 {
		return ShowError(fmt.Errorf("username must be at least 3 characters"))
	}

	if len(password) < 8 {
		return ShowError(fmt.Errorf("password must be at least 8 characters"))
	}

	if password != confirmPassword {
		return ShowError(fmt.Errorf("passwords do not match"))
	}

	return func() tea.Msg {
		if err := c.Register(username, password); err != nil {
			return ErrorMsg{Err: err}
		}
		// After registration, go to login
		return SwitchViewMsg{View: ViewLogin}
	}
}

func (m RegisterModel) View() string {
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

	b.WriteString(titleStyle.Render("📝 LogChat - Register"))
	b.WriteString("\n\n")

	b.WriteString(inputStyle.Render(m.usernameInput.View()))
	b.WriteString("\n")
	b.WriteString(inputStyle.Render(m.passwordInput.View()))
	b.WriteString("\n")
	b.WriteString(inputStyle.Render(m.confirmPasswordInput.View()))
	b.WriteString("\n\n")

	// Register button
	if m.focusIndex == 3 {
		b.WriteString(buttonFocusedStyle.Render("[ Register ]"))
	} else {
		b.WriteString(buttonStyle.Render("[ Register ]"))
	}

	b.WriteString("\n")
	b.WriteString(hintStyle.Render("Press Ctrl+L to login • Ctrl+C to quit"))

	return lipgloss.NewStyle().Padding(2, 4).Render(b.String())
}
