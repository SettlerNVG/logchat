package tui

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/logmessager/client/internal/client"
	"github.com/rs/zerolog/log"
)

// View represents different screens
type View int

const (
	ViewServerSelect View = iota
	ViewLogin
	ViewRegister
	ViewMain
	ViewChat
)

// App is the main TUI application model
type App struct {
	client  *client.Client
	view    View
	width   int
	height  int
	err     error
	eventCh <-chan interface{}
	p2pCh   chan interface{} // Channel for P2P events

	// Sub-models
	serverSelectModel ServerSelectModel
	loginModel        LoginModel
	registerModel     RegisterModel
	mainModel         MainModel
	chatModel         ChatModel
}

// NewApp creates a new TUI application
func NewApp(c *client.Client) *App {
	app := &App{
		client: c,
		view:   ViewServerSelect, // Start with server selection
		p2pCh:  make(chan interface{}, 10),
	}

	app.serverSelectModel = NewServerSelectModel()
	app.loginModel = NewLoginModel()
	app.registerModel = NewRegisterModel()
	app.mainModel = NewMainModel()
	app.chatModel = NewChatModel()

	// If already logged in, skip server selection and go to main view
	if c.IsLoggedIn() {
		app.view = ViewMain
		app.mainModel = app.mainModel.SetUsername(c.GetUsername())
	}

	return app
}

// Init implements tea.Model
func (a *App) Init() tea.Cmd {
	cmds := []tea.Cmd{textinput.Blink}
	// Load contacts and subscribe to events if already logged in
	if a.client.IsLoggedIn() {
		cmds = append(cmds, a.loadContacts(), a.subscribeToEvents())
	}
	return tea.Batch(cmds...)
}

func (a *App) loadContacts() tea.Cmd {
	return func() tea.Msg {
		contacts, err := a.client.ListContacts()
		if err != nil {
			// Check if token is invalid - need to re-login
			if isAuthError(err) {
				log.Warn().Err(err).Msg("Auth error, clearing credentials")
				_ = a.client.Logout()
				return SwitchViewMsg{View: ViewLogin}
			}
			return ErrorMsg{Err: err}
		}
		return ContactsLoadedMsg{Contacts: contacts}
	}
}

// isAuthError checks if error is authentication related
func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "Unauthenticated") || strings.Contains(errStr, "invalid token") || strings.Contains(errStr, "token expired")
}

func (a *App) startP2PHost(session client.SessionInfo) tea.Cmd {
	return func() tea.Msg {
		log.Info().Str("session_id", session.SessionID).Msg("Starting P2P host")
		
		// Setup P2P handlers BEFORE starting host
		a.setupP2PHandlers(session.PeerUsername)
		
		addr, err := a.client.StartP2PHost(
			session.SessionToken,
			session.PeerEncryptionPublicKey,
			session.PeerSignaturePublicKey,
		)
		if err != nil {
			log.Error().Err(err).Msg("Failed to start P2P host")
			return ErrorMsg{Err: err}
		}
		log.Info().Str("address", addr).Msg("P2P host started, reporting to server")

		// Report to server that we're ready
		if err := a.client.ReportHostReady(session.SessionID, addr); err != nil {
			log.Error().Err(err).Msg("Failed to report host ready")
			return ErrorMsg{Err: err}
		}

		return P2PHostStartedMsg{Address: addr}
	}
}

func (a *App) connectToHost(info client.HostReadyInfo, session client.SessionInfo) tea.Cmd {
	return func() tea.Msg {
		log.Info().Str("host_addr", info.HostAddress).Msg("Connecting to P2P host")
		if err := a.client.ConnectP2P(
			info.HostAddress,
			session.SessionToken,
			session.PeerEncryptionPublicKey,
			session.PeerSignaturePublicKey,
		); err != nil {
			log.Error().Err(err).Msg("Failed to connect to P2P host")
			return ErrorMsg{Err: err}
		}

		// Setup P2P handlers after connection
		a.setupP2PHandlers(session.PeerUsername)

		return P2PConnectedMsg{IsHost: false}
	}
}

// setupP2PHandlers sets up message and disconnect handlers for P2P
func (a *App) setupP2PHandlers(peerUsername string) {
	log.Info().Str("peer", peerUsername).Msg("Setting up P2P handlers")

	a.client.SetMessageHandler(func(text string) {
		log.Info().Str("from", peerUsername).Str("text", text).Msg("P2P message received")
		select {
		case a.p2pCh <- P2PMessageReceivedMsg{Text: text, From: peerUsername}:
		default:
			log.Warn().Msg("P2P channel full, dropping message")
		}
	})

	a.client.SetDisconnectHandler(func() {
		log.Info().Msg("P2P disconnected")
		select {
		case a.p2pCh <- P2PDisconnectedMsg{}:
		default:
			log.Warn().Msg("P2P channel full, dropping disconnect event")
		}
	})

	a.client.SetConnectHandler(func() {
		log.Info().Msg("P2P client connected to host")
		select {
		case a.p2pCh <- P2PConnectedMsg{IsHost: true}:
		default:
			log.Warn().Msg("P2P channel full, dropping connect event")
		}
	})
}

// waitForP2PEvent waits for P2P events
func waitForP2PEvent(p2pCh <-chan interface{}) tea.Cmd {
	return func() tea.Msg {
		event, ok := <-p2pCh
		if !ok {
			return nil
		}
		return event
	}
}

func (a *App) subscribeToEvents() tea.Cmd {
	return func() tea.Msg {
		eventCh, err := a.client.SubscribeSessionEvents()
		if err != nil {
			return ErrorMsg{Err: err}
		}
		return SessionEventsSubscribedMsg{EventCh: eventCh}
	}
}

func waitForEvent(eventCh <-chan interface{}) tea.Cmd {
	return func() tea.Msg {
		event, ok := <-eventCh
		if !ok {
			return nil
		}
		switch e := event.(type) {
		case client.ChatRequestInfo:
			return ChatRequestReceivedMsg{Request: e}
		case client.SessionInfo:
			return ChatAcceptedMsg{Session: e}
		case client.HostReadyInfo:
			return HostReadyMsg{Info: e}
		case client.SessionEndedInfo:
			return SessionEndedMsg{SessionID: e.SessionID}
		}
		return nil
	}
}

// Update implements tea.Model
func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "ctrl+q":
			return a, tea.Quit
		}

	case tea.WindowSizeMsg:
		a.width = msg.Width
		a.height = msg.Height

	case SwitchViewMsg:
		a.view = msg.View
		// Load contacts and subscribe when switching to main view
		if msg.View == ViewMain {
			a.mainModel = a.mainModel.SetUsername(a.client.GetUsername())
			return a, tea.Batch(a.loadContacts(), a.subscribeToEvents())
		}
		return a, nil

	case ServerSelectedMsg:
		// Server selected - reconnect client and go to login
		log.Info().Str("address", msg.Address).Msg("Server selected, reconnecting")
		return a, func() tea.Msg {
			if err := a.client.Reconnect(msg.Address); err != nil {
				return ErrorMsg{Err: err}
			}
			return SwitchViewMsg{View: ViewLogin}
		}

	case SessionEventsSubscribedMsg:
		// Save channel and start listening for events
		a.eventCh = msg.EventCh
		return a, waitForEvent(msg.EventCh)

	case ChatRequestReceivedMsg:
		// Pass to main model and continue listening
		log.Info().Str("from", msg.Request.FromUsername).Str("request_id", msg.Request.RequestID).Msg("Chat request received")
		a.mainModel, _ = a.mainModel.Update(msg, a.client)
		if a.eventCh != nil {
			return a, waitForEvent(a.eventCh)
		}
		return a, nil

	case ChatAcceptedMsg:
		// Session started - setup P2P and switch to chat view
		// Ignore if already in chat view (prevents double processing)
		if a.view == ViewChat {
			log.Debug().Msg("Already in chat view, ignoring ChatAcceptedMsg")
			if a.eventCh != nil {
				return a, waitForEvent(a.eventCh)
			}
			return a, nil
		}

		log.Info().Str("session_id", msg.Session.SessionID).Str("peer", msg.Session.PeerUsername).Bool("is_host", msg.Session.IsHost).Msg("Session started, switching to chat")
		// Create fresh ChatModel for new session - messages only in RAM
		a.chatModel = NewChatModel().SetSession(msg.Session)
		a.view = ViewChat
		a.err = nil // Clear any previous errors

		var cmds []tea.Cmd
		if a.eventCh != nil {
			cmds = append(cmds, waitForEvent(a.eventCh))
		}

		if msg.Session.IsHost {
			// I'm the host - start P2P server
			log.Info().Msg("I am the host, starting P2P server")
			cmds = append(cmds, a.startP2PHost(msg.Session))
		} else {
			// I'm the client - wait for HostReady event
			log.Info().Msg("I am the client, waiting for host ready event")
		}

		return a, tea.Batch(cmds...)

	case HostReadyMsg:
		// Host is ready - connect as client
		log.Info().Str("session_id", msg.Info.SessionID).Str("host_addr", msg.Info.HostAddress).Msg("Host ready, connecting as client")
		
		// Create session info from chatModel
		session := client.SessionInfo{
			SessionID:                a.chatModel.sessionID,
			SessionToken:             a.chatModel.sessionToken,
			PeerUsername:             a.chatModel.peerUsername,
			PeerEncryptionPublicKey:  a.chatModel.peerEncryptionPublicKey,
			PeerSignaturePublicKey:   a.chatModel.peerSignaturePublicKey,
		}
		
		cmd := a.connectToHost(msg.Info, session)
		var cmds []tea.Cmd
		cmds = append(cmds, cmd)
		if a.eventCh != nil {
			cmds = append(cmds, waitForEvent(a.eventCh))
		}
		return a, tea.Batch(cmds...)

	case P2PConnectedMsg:
		// P2P connection established
		log.Info().Bool("is_host", msg.IsHost).Msg("P2P connected")
		a.chatModel.connected = true
		// Start listening for P2P events
		return a, waitForP2PEvent(a.p2pCh)

	case P2PMessageReceivedMsg:
		// Message received from P2P
		log.Info().Str("from", msg.From).Str("text", msg.Text).Msg("Forwarding P2P message to chat")
		a.chatModel, _ = a.chatModel.Update(MessageReceivedMsg{From: msg.From, Text: msg.Text}, a.client)
		return a, waitForP2PEvent(a.p2pCh)

	case P2PDisconnectedMsg:
		// P2P disconnected
		log.Info().Msg("P2P disconnected, returning to main")
		// End session on server
		if a.chatModel.sessionID != "" {
			if err := a.client.EndSession(a.chatModel.sessionID); err != nil {
				log.Error().Err(err).Msg("Failed to end session on server")
			}
		}
		a.chatModel = NewChatModel() // Clear messages from RAM
		a.client.EndChat()
		a.view = ViewMain
		a.mainModel = a.mainModel.SetUsername(a.client.GetUsername())
		return a, tea.Batch(a.loadContacts(), waitForEvent(a.eventCh))

	case P2PHostStartedMsg:
		// P2P host started, waiting for client to connect
		log.Info().Str("address", msg.Address).Msg("P2P host started, waiting for client")
		// Don't set connected yet - wait for P2PConnectedMsg from connect handler
		return a, waitForP2PEvent(a.p2pCh)

	case SessionEndedMsg:
		// Other user ended the session
		log.Info().Str("session_id", msg.SessionID).Msg("Session ended by peer")
		// End session on our side too
		if msg.SessionID != "" {
			if err := a.client.EndSession(msg.SessionID); err != nil {
				log.Error().Err(err).Msg("Failed to end session on server")
			}
		}
		a.chatModel = NewChatModel() // Clear messages from RAM
		a.client.EndChat() // Clean up P2P
		a.view = ViewMain
		a.mainModel = a.mainModel.SetUsername(a.client.GetUsername())
		a.err = nil
		return a, tea.Batch(a.loadContacts(), waitForEvent(a.eventCh))

	case ChatDisconnectedMsg:
		// User ended the chat locally
		log.Info().Msg("Chat disconnected locally")
		a.chatModel = NewChatModel() // Clear messages from RAM
		a.view = ViewMain
		a.mainModel = a.mainModel.SetUsername(a.client.GetUsername())
		a.err = nil
		var cmds []tea.Cmd
		cmds = append(cmds, a.loadContacts())
		if a.eventCh != nil {
			cmds = append(cmds, waitForEvent(a.eventCh))
		}
		return a, tea.Batch(cmds...)

	case ErrorMsg:
		a.err = msg.Err
		return a, nil

	case ClearErrorMsg:
		a.err = nil
		return a, nil
	}

	// Delegate to current view
	var cmd tea.Cmd
	switch a.view {
	case ViewServerSelect:
		a.serverSelectModel, cmd = a.serverSelectModel.Update(msg)
	case ViewLogin:
		a.loginModel, cmd = a.loginModel.Update(msg, a.client)
	case ViewRegister:
		a.registerModel, cmd = a.registerModel.Update(msg, a.client)
	case ViewMain:
		a.mainModel, cmd = a.mainModel.Update(msg, a.client)
	case ViewChat:
		a.chatModel, cmd = a.chatModel.Update(msg, a.client)
	}

	return a, cmd
}

// View implements tea.Model
func (a *App) View() string {
	var content string

	switch a.view {
	case ViewServerSelect:
		content = a.serverSelectModel.View()
	case ViewLogin:
		content = a.loginModel.View()
	case ViewRegister:
		content = a.registerModel.View()
	case ViewMain:
		content = a.mainModel.View()
	case ViewChat:
		content = a.chatModel.View()
	}

	// Add error display if present
	if a.err != nil {
		errorStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("196")).
			Bold(true).
			Padding(0, 1)
		// Show user-friendly error message
		content += "\n" + errorStyle.Render("✗ "+friendlyError(a.err))
	}

	return content
}

// Messages

type SwitchViewMsg struct {
	View View
}

type ErrorMsg struct {
	Err error
}

type ClearErrorMsg struct{}

type SessionEventsSubscribedMsg struct {
	EventCh <-chan interface{}
}

type HostReadyMsg struct {
	Info client.HostReadyInfo
}

type P2PConnectedMsg struct {
	IsHost bool
}

type P2PHostStartedMsg struct {
	Address string
}

type P2PMessageReceivedMsg struct {
	Text string
	From string
}

type P2PDisconnectedMsg struct{}

type SessionEndedMsg struct {
	SessionID string
}

// Commands

func SwitchView(v View) tea.Cmd {
	return func() tea.Msg {
		return SwitchViewMsg{View: v}
	}
}

func ShowError(err error) tea.Cmd {
	return func() tea.Msg {
		return ErrorMsg{Err: err}
	}
}

func ClearError() tea.Cmd {
	return func() tea.Msg {
		return ClearErrorMsg{}
	}
}
