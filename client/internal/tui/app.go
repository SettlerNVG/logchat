package tui

import (
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/logmessager/client/internal/client"
)

// View represents different screens
type View int

const (
	ViewLogin View = iota
	ViewRegister
	ViewMain
	ViewChat
)

// App is the main TUI application model
type App struct {
	client *client.Client
	view   View
	width  int
	height int
	err    error

	// Sub-models
	loginModel    LoginModel
	registerModel RegisterModel
	mainModel     MainModel
	chatModel     ChatModel
}

// NewApp creates a new TUI application
func NewApp(c *client.Client) *App {
	app := &App{
		client: c,
		view:   ViewLogin,
	}

	app.loginModel = NewLoginModel()
	app.registerModel = NewRegisterModel()
	app.mainModel = NewMainModel()
	app.chatModel = NewChatModel()

	// If already logged in, go to main view
	if c.IsLoggedIn() {
		app.view = ViewMain
	}

	return app
}

// Init implements tea.Model
func (a *App) Init() tea.Cmd {
	return textinput.Blink
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
		return a, nil

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
		content += "\n" + errorStyle.Render("Error: "+a.err.Error())
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
