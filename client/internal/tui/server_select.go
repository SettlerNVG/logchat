package tui

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ServerSelectModel handles server selection screen
type ServerSelectModel struct {
	servers      []ServerInfo
	selectedIdx  int
	customInput  textinput.Model
	mode         string // "list" or "custom"
	focusIndex   int    // 0 = list, 1 = custom input, 2 = connect button
}

// ServerInfo represents a known server
type ServerInfo struct {
	Name    string
	Address string
	Desc    string
}

// NewServerSelectModel creates a new server selection model
func NewServerSelectModel() ServerSelectModel {
	ti := textinput.New()
	ti.Placeholder = "server.example.com:50051"
	ti.CharLimit = 100
	ti.Width = 50

	// Default known servers
	servers := []ServerInfo{
		{
			Name:    "Localhost",
			Address: "localhost:50051",
			Desc:    "Local development server",
		},
		{
			Name:    "Custom Server",
			Address: "",
			Desc:    "Enter custom server address",
		},
	}

	return ServerSelectModel{
		servers:     servers,
		selectedIdx: 0,
		customInput: ti,
		mode:        "list",
		focusIndex:  0,
	}
}

// Update handles server selection updates
func (m ServerSelectModel) Update(msg tea.Msg) (ServerSelectModel, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if m.mode == "list" && m.selectedIdx > 0 {
				m.selectedIdx--
			}
			return m, nil

		case "down", "j":
			if m.mode == "list" && m.selectedIdx < len(m.servers)-1 {
				m.selectedIdx++
			}
			return m, nil

		case "enter":
			if m.mode == "list" {
				selected := m.servers[m.selectedIdx]
				if selected.Name == "Custom Server" {
					// Switch to custom input mode
					m.mode = "custom"
					m.customInput.Focus()
					return m, textinput.Blink
				} else {
					// Connect to selected server
					addr := strings.TrimSpace(selected.Address)
					return m, func() tea.Msg {
						return ServerSelectedMsg{Address: addr}
					}
				}
			} else if m.mode == "custom" {
				// Connect to custom server
				addr := strings.TrimSpace(m.customInput.Value())
				if addr != "" {
					return m, func() tea.Msg {
						return ServerSelectedMsg{Address: addr}
					}
				}
			}
			return m, nil

		case "esc":
			if m.mode == "custom" {
				// Go back to list mode
				m.mode = "list"
				m.customInput.Blur()
				return m, nil
			}
			return m, nil
		}
	}

	// Update custom input if in custom mode
	if m.mode == "custom" {
		m.customInput, cmd = m.customInput.Update(msg)
		return m, cmd
	}

	return m, nil
}

// View renders the server selection screen
func (m ServerSelectModel) View() string {
	var s strings.Builder

	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("86")).
		Padding(1, 0)

	s.WriteString(titleStyle.Render("🌐 Select Server"))
	s.WriteString("\n\n")

	if m.mode == "list" {
		// Show server list
		for i, server := range m.servers {
			cursor := " "
			if i == m.selectedIdx {
				cursor = ">"
			}

			nameStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("86"))
			descStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))

			s.WriteString(cursor + " ")
			s.WriteString(nameStyle.Render(server.Name))
			if server.Address != "" {
				s.WriteString(" - " + server.Address)
			}
			s.WriteString("\n")
			s.WriteString("  " + descStyle.Render(server.Desc))
			s.WriteString("\n\n")
		}

		helpStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
		s.WriteString("\n")
		s.WriteString(helpStyle.Render("↑/↓: Navigate • Enter: Select • Ctrl+C: Quit"))
	} else {
		// Show custom input
		s.WriteString("Enter server address:\n\n")
		s.WriteString(m.customInput.View())
		s.WriteString("\n\n")

		helpStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
		s.WriteString(helpStyle.Render("Enter: Connect • Esc: Back • Ctrl+C: Quit"))
	}

	return s.String()
}

// ServerSelectedMsg is sent when a server is selected
type ServerSelectedMsg struct {
	Address string
}
