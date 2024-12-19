package logics

import (
	"crypto/tls"
	"goauth/secrets"
	"io"
	"net/smtp"
	"strings"
)

// Команда на отправку уведомления по электронной почте.
type NotificationCommand struct {
	// Адрес электронной почты получателя.
	ReceiverEmail string

	// Тема письма.
	MessageSubject string

	// Содержание письма.
	MessageBody string
}

// Обработчик команды на отправку уведомления по электронной почте.
type NotificationCommandHandler struct {
	// Обрабатываемая команда.
	Command *NotificationCommand

	_client *smtp.Client
	_writer io.WriteCloser
}

// Обработать команду на отправку уведомления по электронной почте.
func (s *NotificationCommandHandler) Handle() {
	s.beginTransaction()

	s.writeMessage()

	s.closeTransaction()
}

// 1-й уровень абстракции.

func (s *NotificationCommandHandler) beginTransaction() {
	var err error

	err = s.client().Auth(s.auth())
	if err != nil {
		panic(err)
	}

	err = s.client().Mail(secrets.SENDER_EMAIL)
	if err != nil {
		panic(err)
	}

	err = s.client().Rcpt(s.Command.ReceiverEmail)
	if err != nil {
		panic(err)
	}
}

func (s *NotificationCommandHandler) writeMessage() {
	_, err := s.writer().Write([]byte(s.message()))
	if err != nil {
		panic(err)
	}
}

func (s *NotificationCommandHandler) closeTransaction() {
	s.closeWriter()
	s.client().Quit()
}

// 2-й уровень абстракции.

func (s *NotificationCommandHandler) auth() smtp.Auth {
	return smtp.PlainAuth("", secrets.SENDER_USER_NAME, secrets.SENDER_PASSWORD, secrets.SMTP_SERVER_HOST)
}

func (s *NotificationCommandHandler) message() string {
	return strings.Join([]string{
		"From: " + secrets.SENDER_EMAIL,
		"To: " + s.Command.ReceiverEmail,
		"Subject: " + s.Command.MessageSubject,
		s.Command.MessageBody,
	}, "\r\n")
}

func (s *NotificationCommandHandler) closeWriter() {
	err := s.writer().Close()
	if err != nil {
		panic(err)
	}
}

// 3-й уровень абстракции.

func (s *NotificationCommandHandler) writer() io.WriteCloser {
	if s._writer == nil {
		s._writer = s.createWriter()
	}

	return s._writer
}

// 4-й уровень абстракции.

func (s *NotificationCommandHandler) createWriter() io.WriteCloser {
	writer, err := s.client().Data()
	if err != nil {
		panic(err)
	}

	return writer
}

// 5-й уровень абстракции.

func (s *NotificationCommandHandler) client() *smtp.Client {
	if s._client == nil {
		s._client = s.createClient()
	}

	return s._client
}

// 6-й уровень абстракции.

func (s *NotificationCommandHandler) createClient() *smtp.Client {
	client, err := smtp.NewClient(s.createConnection(), secrets.SMTP_SERVER_HOST)
	if err != nil {
		panic(err)
	}

	return client
}

// 7-й уровень абстракции.

func (s *NotificationCommandHandler) createConnection() *tls.Conn {
	connection, err := tls.Dial("tcp", secrets.SMTP_SERVER_ADDRESS, s.tlsConfig())
	if err != nil {
		panic(err)
	}

	return connection
}

// 8-й уровень абстракции.

func (s *NotificationCommandHandler) tlsConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         secrets.SMTP_SERVER_HOST,
	}
}
