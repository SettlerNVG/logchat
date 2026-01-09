package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/logmessager/client/internal/client"
	"github.com/rs/zerolog/log"
)

type MainModel struct {
	contacts        []client.ContactInfo
	selectedIdx     int
	showAddForm     bool
	addInput        string
	errorMsg        string
	successMsg      string
	pendingRequest  *client.ChatRequestInfo
	currentUsername string
}

func NewMainModel() MainModel {
	return MainModel{
		contacts:    []client.ContactInfo{},
		selectedIdx: 0,
	}
}

func (m MainModel) SetUsername(username string) MainModel {
	m.currentUsername = username
	return m
}

func (m MainModel) Update(msg tea.Msg, c *client.Client) (MainModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		// Handle pending chat request
		if m.pendingRequest != nil {
			switch msg.String() {
			case "y", "Y":
				req := m.pendingRequest
				m.pendingRequest = nil
				return m, m.acceptChat(c, req.RequestID)
			case "n", "N":
				req := m.pendingRequest
				m.pendingRequest = nil
				return m, m.declineChat(c, req.RequestID)
			}
			return m, nil
		}

		// Handle add contact form
		if m.showAddForm {
			switch msg.String() {
			case "enter":
				if m.addInput != "" {
					return m, m.addContact(c, m.addInput)
				}
			case "esc":
				m.showAddForm = false
				m.addInput = ""
				m.errorMsg = ""
			case "backspace":
				if len(m.addInput) > 0 {
					m.addInput = m.addInput[:len(m.addInput)-1]
				}
			default:
				if len(msg.String()) == 1 {
					m.addInput += msg.String()
				}
			}
			return m, nil
		}

		// Normal mode
		switch msg.String() {
		case "up", "k":
			if m.selectedIdx > 0 {
				m.selectedIdx--
			}

		case "down", "j":
			if m.selectedIdx < len(m.contacts)-1 {
				m.selectedIdx++
			}

		case "enter":
			if len(m.contacts) > 0 && m.selectedIdx < len(m.contacts) {
				contact := m.contacts[m.selectedIdx]
				return m, m.startChat(c, contact.UserID)
			}

		case "a":
			m.showAddForm = true
			m.addInput = ""
			m.errorMsg = ""
			m.successMsg = ""

		case "d":
			if len(m.contacts) > 0 && m.selectedIdx < len(m.contacts) {
				contact := m.contacts[m.selectedIdx]
				return m, m.removeContact(c, contact.ID)
			}

		case "r":
			m.successMsg = ""
			m.errorMsg = ""
			return m, m.refreshContacts(c)

		case "l":
			return m, m.logout(c)
		}

	case ContactsLoadedMsg:
		m.contacts = msg.Contacts
		if m.selectedIdx >= len(m.contacts) && len(m.contacts) > 0 {
			m.selectedIdx = len(m.contacts) - 1
		}
		if len(m.contacts) == 0 {
			m.selectedIdx = 0
		}

	case ContactAddedMsg:
		m.showAddForm = false
		m.addInput = ""
		m.successMsg = fmt.Sprintf("Added %s to contacts", msg.Contact.Username)
		return m, m.refreshContacts(c)

	case ContactRemovedMsg:
		m.successMsg = "Contact removed"
		return m, m.refreshContacts(c)

	case ChatRequestReceivedMsg:
		m.pendingRequest = &msg.Request

	case ChatRequestSentMsg:
		m.successMsg = "Chat request sent, waiting for response..."

	case ChatStartedMsg:
		return m, SwitchView(ViewChat)

	case ErrorMsg:
		m.errorMsg = msg.Err.Error()
	}

	return m, nil
}

func (m MainModel) refreshContacts(c *client.Client) tea.Cmd {
	return func() tea.Msg {
		contacts, err := c.ListContacts()
		if err != nil {
			return ErrorMsg{Err: err}
		}
		return ContactsLoadedMsg{Contacts: contacts}
	}
}

func (m MainModel) addContact(c *client.Client, username string) tea.Cmd {
	return func() tea.Msg {
		contact, err := c.AddContact(username, "")
		if err != nil {
			return ErrorMsg{Err: err}
		}
		return ContactAddedMsg{Contact: *contact}
	}
}

func (m MainModel) removeContact(c *client.Client, contactID string) tea.Cmd {
	return func() tea.Msg {
		if err := c.RemoveContact(contactID); err != nil {
			return ErrorMsg{Err: err}
		}
		return ContactRemovedMsg{}
	}
}

func (m MainModel) startChat(c *client.Client, userID string) tea.Cmd {
	return func() tea.Msg {
		log.Info().Str("target_user_id", userID).Msg("Requesting chat")
		_, err := c.RequestChat(userID)
		if err != nil {
			log.Error().Err(err).Str("target_user_id", userID).Msg("Failed to request chat")
			return ErrorMsg{Err: err}
		}
		log.Info().Msg("Chat request sent successfully")
		// Don't switch to chat yet - wait for the other user to accept
		// and for session_started event
		return ChatRequestSentMsg{}
	}
}

func (m MainModel) acceptChat(c *client.Client, requestID string) tea.Cmd {
	return func() tea.Msg {
		log.Info().Str("request_id", requestID).Msg("Accepting chat request")
		session, err := c.AcceptChat(requestID)
		if err != nil {
			log.Error().Err(err).Str("request_id", requestID).Msg("Failed to accept chat")
			return ErrorMsg{Err: err}
		}
		log.Info().Str("session_id", session.SessionID).Bool("is_host", session.IsHost).Msg("Chat accepted")
		return ChatAcceptedMsg{Session: *session}
	}
}

func (m MainModel) declineChat(c *client.Client, requestID string) tea.Cmd {
	return func() tea.Msg {
		if err := c.DeclineChat(requestID); err != nil {
			return ErrorMsg{Err: err}
		}
		return ChatDeclinedMsg{}
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

	usernameStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("214")).
		Bold(true)

	contactStyle := lipgloss.NewStyle().
		Padding(0, 2)

	selectedStyle := contactStyle.
		Background(lipgloss.Color("57")).
		Foreground(lipgloss.Color("229"))

	onlineStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("46"))

	offlineStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("241"))

	hintStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("241")).
		MarginTop(2)

	errorStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("196"))

	successStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("46"))

	inputStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("86")).
		Padding(0, 1)

	requestStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("214")).
		Padding(1, 2).
		MarginBottom(1)

	b.WriteString(titleStyle.Render("💬 LogChat"))
	b.WriteString("  ")
	if m.currentUsername != "" {
		b.WriteString(usernameStyle.Render("@" + m.currentUsername))
	}
	b.WriteString("\n\n")

	// Show pending chat request
	if m.pendingRequest != nil {
		b.WriteString(requestStyle.Render(
			fmt.Sprintf("📨 Chat request from %s\n\nPress Y to accept, N to decline",
				m.pendingRequest.FromUsername)))
		b.WriteString("\n\n")
		return lipgloss.NewStyle().Padding(2, 4).Render(b.String())
	}

	// Show add contact form
	if m.showAddForm {
		b.WriteString(headerStyle.Render("Add Contact:"))
		b.WriteString("\n\n")
		b.WriteString("Username: ")
		b.WriteString(inputStyle.Render(m.addInput + "█"))
		b.WriteString("\n\n")
		if m.errorMsg != "" {
			b.WriteString(errorStyle.Render("Error: " + m.errorMsg))
			b.WriteString("\n\n")
		}
		b.WriteString(hintStyle.Render("Enter to add • Esc to cancel"))
		return lipgloss.NewStyle().Padding(2, 4).Render(b.String())
	}

	b.WriteString(headerStyle.Render("Contacts:"))
	b.WriteString("\n\n")

	if m.successMsg != "" {
		b.WriteString(successStyle.Render("✓ " + m.successMsg))
		b.WriteString("\n\n")
	}

	if m.errorMsg != "" {
		b.WriteString(errorStyle.Render("✗ " + m.errorMsg))
		b.WriteString("\n\n")
	}

	if len(m.contacts) == 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("241")).
			Render("  No contacts yet. Press 'A' to add."))
	} else {
		for i, contact := range m.contacts {
			var status string
			if contact.IsOnline {
				status = onlineStyle.Render("●")
			} else {
				status = offlineStyle.Render("○")
			}

			name := contact.Username
			if contact.Nickname != "" {
				name = fmt.Sprintf("%s (%s)", contact.Nickname, contact.Username)
			}

			line := fmt.Sprintf("%s %s", status, name)

			if i == m.selectedIdx {
				b.WriteString(selectedStyle.Render(line))
			} else {
				b.WriteString(contactStyle.Render(line))
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("\n")
	b.WriteString(hintStyle.Render("↑/↓ navigate • Enter chat • A add • D delete • R refresh • L logout"))

	return lipgloss.NewStyle().Padding(2, 4).Render(b.String())
}

// Messages

type ContactsLoadedMsg struct {
	Contacts []client.ContactInfo
}

type ContactAddedMsg struct {
	Contact client.ContactInfo
}

type ContactRemovedMsg struct{}

type ChatStartedMsg struct{}

type ChatRequestSentMsg struct{}

type ChatRequestReceivedMsg struct {
	Request client.ChatRequestInfo
}

type ChatAcceptedMsg struct {
	Session client.SessionInfo
}

type ChatDeclinedMsg struct{}
