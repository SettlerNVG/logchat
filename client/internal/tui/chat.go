package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/logmessager/client/internal/client"
	"github.com/rs/zerolog/log"
)

type ChatMessage struct {
	From      string
	Text      string
	Timestamp time.Time
	IsMe      bool
}

type ChatModel struct {
	peerUsername             string
	isHost                   bool
	connected                bool
	messages                 []ChatMessage
	input                    textinput.Model
	viewport                 viewport.Model
	width                    int
	height                   int
	sessionID                string
	sessionToken             string
	peerEncryptionPublicKey  []byte
	peerSignaturePublicKey   []byte
}

func NewChatModel() ChatModel {
	input := textinput.New()
	input.Placeholder = "Type a message..."
	input.Focus()
	input.CharLimit = 1000
	input.Width = 50

	return ChatModel{
		messages: []ChatMessage{},
		input:    input,
	}
}

func (m ChatModel) SetSession(session client.SessionInfo) ChatModel {
	m.peerUsername = session.PeerUsername
	m.isHost = session.IsHost
	m.sessionID = session.SessionID
	m.sessionToken = session.SessionToken
	m.peerEncryptionPublicKey = session.PeerEncryptionPublicKey
	m.peerSignaturePublicKey = session.PeerSignaturePublicKey
	return m
}

func (m ChatModel) Update(msg tea.Msg, c *client.Client) (ChatModel, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			if text := strings.TrimSpace(m.input.Value()); text != "" {
				// Send message
				cmds = append(cmds, m.sendMessage(c, text))
				m.input.SetValue("")
			}

		case "esc":
			// End chat
			return m, m.endChat(c)
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.viewport.Width = msg.Width - 8
		m.viewport.Height = msg.Height - 10

	case MessageReceivedMsg:
		log.Info().Str("from", msg.From).Str("text", msg.Text).Int("messages_before", len(m.messages)).Msg("MessageReceivedMsg in chat.Update")
		m.messages = append(m.messages, ChatMessage{
			From:      msg.From,
			Text:      msg.Text,
			Timestamp: time.Now(),
			IsMe:      false,
		})
		log.Info().Int("messages_after", len(m.messages)).Msg("Messages updated")
		m.viewport.SetContent(m.renderMessages())
		m.viewport.GotoBottom()

	case MessageSentMsg:
		log.Info().Str("text", msg.Text).Int("messages_before", len(m.messages)).Msg("MessageSentMsg in chat.Update")
		m.messages = append(m.messages, ChatMessage{
			From:      "You",
			Text:      msg.Text,
			Timestamp: time.Now(),
			IsMe:      true,
		})
		log.Info().Int("messages_after", len(m.messages)).Msg("Messages updated")
		m.viewport.SetContent(m.renderMessages())
		m.viewport.GotoBottom()

	case ChatConnectedMsg:
		m.peerUsername = msg.PeerUsername
		m.isHost = msg.IsHost
		m.connected = true

	case ChatDisconnectedMsg:
		m.connected = false
		// Don't switch view here - let app.go handle it
	}

	// Update input
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	cmds = append(cmds, cmd)

	// Update viewport
	m.viewport, cmd = m.viewport.Update(msg)
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

func (m ChatModel) sendMessage(c *client.Client, text string) tea.Cmd {
	return func() tea.Msg {
		if err := c.SendMessage(text); err != nil {
			return ErrorMsg{Err: err}
		}
		return MessageSentMsg{Text: text}
	}
}

func (m ChatModel) endChat(c *client.Client) tea.Cmd {
	return func() tea.Msg {
		log.Info().Str("session_id", m.sessionID).Msg("Ending chat session")
		if m.sessionID != "" {
			if err := c.EndSession(m.sessionID); err != nil {
				log.Error().Err(err).Msg("Failed to end session on server")
			}
		}
		c.EndChat()
		return ChatDisconnectedMsg{}
	}
}

func (m ChatModel) renderMessages() string {
	var b strings.Builder

	myStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("86")).
		Align(lipgloss.Right)

	theirStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("212"))

	timeStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("241")).
		Italic(true)

	for _, msg := range m.messages {
		timestamp := timeStyle.Render(msg.Timestamp.Format("15:04"))

		if msg.IsMe {
			b.WriteString(fmt.Sprintf("%s %s: %s\n",
				timestamp,
				myStyle.Render("You"),
				msg.Text,
			))
		} else {
			b.WriteString(fmt.Sprintf("%s %s: %s\n",
				timestamp,
				theirStyle.Render(msg.From),
				msg.Text,
			))
		}
	}

	return b.String()
}

func (m ChatModel) View() string {
	var b strings.Builder

	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("86"))

	statusStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("241"))

	borderStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("57")).
		Padding(1).
		Width(60).
		Height(10)

	hintStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("241")).
		MarginTop(1)

	// Header
	role := "client"
	if m.isHost {
		role = "host"
	}

	header := fmt.Sprintf("💬 Chat with %s", m.peerUsername)
	b.WriteString(titleStyle.Render(header))
	b.WriteString("  ")
	b.WriteString(statusStyle.Render(fmt.Sprintf("(%s)", role)))

	if m.connected {
		b.WriteString("  ")
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Render("● connected"))
	} else {
		b.WriteString("  ")
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("● disconnected"))
	}

	// Debug: show message count
	b.WriteString(fmt.Sprintf("  [%d msgs]", len(m.messages)))

	b.WriteString("\n\n")

	// Messages - render directly instead of using viewport
	messagesContent := m.renderMessages()
	if messagesContent == "" {
		messagesContent = "No messages yet..."
	}
	b.WriteString(borderStyle.Render(messagesContent))
	b.WriteString("\n\n")

	// Input
	b.WriteString("> ")
	b.WriteString(m.input.View())
	b.WriteString("\n")

	b.WriteString(hintStyle.Render("Enter to send • Esc to end chat"))

	return lipgloss.NewStyle().Padding(2, 4).Render(b.String())
}

// Messages

type MessageReceivedMsg struct {
	From string
	Text string
}

type MessageSentMsg struct {
	Text string
}

type ChatConnectedMsg struct {
	PeerUsername string
	IsHost       bool
}

type ChatDisconnectedMsg struct{}
