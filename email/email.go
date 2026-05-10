// Package email defines the EmailSender interface and built-in implementations.
package email

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"log"
	"os"
	"path/filepath"
)

//go:embed templates/*.html
var defaultTemplates embed.FS

// Sender is the interface chiauth uses to send auth emails.
// Implement this interface to use any email provider (Resend, SendGrid, etc.).
type Sender interface {
	SendVerification(to string, data VerificationData) error
	SendPasswordReset(to string, data PasswordResetData) error
	SendLoginAlert(to string, data LoginAlertData) error
}

// VerificationData is injected into the verification email template.
type VerificationData struct {
	FirstName       string
	VerificationURL string // full URL with token
	Token           string // raw token — for API-only (Postman) consumers
	ExpiresIn       string // e.g. "24 hours"
	AppName         string
	SupportEmail    string
}

// PasswordResetData is injected into the password reset email template.
type PasswordResetData struct {
	FirstName    string
	ResetURL     string
	Token        string // raw token for API-only consumers
	ExpiresIn    string
	IPAddress    string // IP that requested the reset
	AppName      string
	SupportEmail string
}

// LoginAlertData is injected into the login alert email template.
type LoginAlertData struct {
	FirstName    string
	IPAddress    string
	DeviceInfo   string
	Time         string
	AppName      string
	SupportEmail string
}

// STDOUT SENDER (dev mode — no email setup needed)


// StdoutSender prints email content to stdout instead of sending real emails.
// This is the default when no EmailSender is configured.
// Perfect for backend-only developers using Postman.
type StdoutSender struct{}

func (s *StdoutSender) SendVerification(to string, data VerificationData) error {
	log.Printf("\n========== [chiauth] VERIFICATION EMAIL ==========")
	log.Printf("To:    %s", to)
	log.Printf("Token: %s", data.Token)
	log.Printf("URL:   %s", data.VerificationURL)
	log.Printf("==================================================\n")
	return nil
}

func (s *StdoutSender) SendPasswordReset(to string, data PasswordResetData) error {
	log.Printf("\n========== [chiauth] PASSWORD RESET EMAIL ==========")
	log.Printf("To:    %s", to)
	log.Printf("Token: %s", data.Token)
	log.Printf("URL:   %s", data.ResetURL)
	log.Printf("====================================================\n")
	return nil
}

func (s *StdoutSender) SendLoginAlert(to string, data LoginAlertData) error {
	log.Printf("\n========== [chiauth] LOGIN ALERT EMAIL ==========")
	log.Printf("To:         %s", to)
	log.Printf("IP:         %s", data.IPAddress)
	log.Printf("Device:     %s", data.DeviceInfo)
	log.Printf("Time:       %s", data.Time)
	log.Printf("=================================================\n")
	return nil
}


// SMTP SENDER (production default via gomail)

// SMTPConfig holds the configuration for the SMTP sender.
type SMTPConfig struct {
	Host         string
	Port         int
	Username     string
	Password     string
	FromAddress  string
	FromName     string
	TemplatesDir string // optional: path to custom templates directory
}

// SMTPSender sends real emails via SMTP using gomail.
// Import gopkg.in/gomail.v2 in your application to use this.
type SMTPSender struct {
	config    SMTPConfig
	templates map[string]*template.Template
}

// NewSMTPSender creates an SMTPSender, loading templates from disk or embedded defaults.
func NewSMTPSender(cfg SMTPConfig) (*SMTPSender, error) {
	s := &SMTPSender{
		config:    cfg,
		templates: make(map[string]*template.Template),
	}
	names := []string{"verification.html", "password_reset.html", "login_alert.html"}
	for _, name := range names {
		tmpl, err := s.loadTemplate(name, cfg.TemplatesDir)
		if err != nil {
			return nil, fmt.Errorf("chiauth: failed to load email template %s: %w", name, err)
		}
		s.templates[name] = tmpl
	}
	return s, nil
}

// loadTemplate returns the template from the custom dir if it exists,
// otherwise falls back to the embedded default.
func (s *SMTPSender) loadTemplate(name, customDir string) (*template.Template, error) {
	if customDir != "" {
		path := filepath.Join(customDir, name)
		if _, err := os.Stat(path); err == nil {
			return template.ParseFiles(path)
		}
	}
	content, err := defaultTemplates.ReadFile("templates/" + name)
	if err != nil {
		return nil, err
	}
	return template.New(name).Parse(string(content))
}

func (s *SMTPSender) render(name string, data interface{}) (string, error) {
	tmpl, ok := s.templates[name]
	if !ok {
		return "", fmt.Errorf("template %s not found", name)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// sendEmail is the internal SMTP dispatch.
// NOTE: gomail.v2 import is intentionally left out so the package compiles
// without requiring SMTP in every consumer. Use the StdoutSender in dev,
// or implement your own Sender with gomail/Resend/SendGrid as needed.
// See the docs for a full gomail example.
func (s *SMTPSender) sendEmail(to, subject, body string) error {
	// gomail example (add gopkg.in/gomail.v2 to your app's go.mod):
	//
	//   m := gomail.NewMessage()
	//   m.SetHeader("From", gomail.FormatAddress(s.config.FromAddress, s.config.FromName))
	//   m.SetHeader("To", to)
	//   m.SetHeader("Subject", subject)
	//   m.SetBody("text/html", body)
	//   d := gomail.NewDialer(s.config.Host, s.config.Port, s.config.Username, s.config.Password)
	//   return d.DialAndSend(m)
	_ = to
	_ = subject
	_ = body
	return fmt.Errorf("SMTPSender.sendEmail: add gopkg.in/gomail.v2 to your go.mod and uncomment the implementation")
}

func (s *SMTPSender) SendVerification(to string, data VerificationData) error {
	body, err := s.render("verification.html", data)
	if err != nil {
		return err
	}
	return s.sendEmail(to, fmt.Sprintf("[%s] Verify your email address", data.AppName), body)
}

func (s *SMTPSender) SendPasswordReset(to string, data PasswordResetData) error {
	body, err := s.render("password_reset.html", data)
	if err != nil {
		return err
	}
	return s.sendEmail(to, fmt.Sprintf("[%s] Reset your password", data.AppName), body)
}

func (s *SMTPSender) SendLoginAlert(to string, data LoginAlertData) error {
	body, err := s.render("login_alert.html", data)
	if err != nil {
		return err
	}
	return s.sendEmail(to, fmt.Sprintf("[%s] New login detected", data.AppName), body)
}
