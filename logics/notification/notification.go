package notification

import (
	"crypto/tls"
	"goauth/secrets"
	"io"
	"net/smtp"
	"strings"
)

// Команда на отправку уведомления по электронной почте.
type Command struct {
	// Адрес электронной почты получателя.
	ReceiverEmail string

	// Тема письма.
	MessageSubject string

	// Содержание письма.
	MessageBody string
}

// Обработчик команды на отправку уведомления по электронной почте.
type CommandHandler struct {
	// Обрабатываемая команда.
	Command *Command

	_client *smtp.Client
	_writer io.WriteCloser
}

// Обработать команду на отправку уведомления по электронной почте.
func (s *CommandHandler) Handle() {
	s.beginTransaction()

	s.writeMessage()

	s.closeTransaction()
}

// 1-й уровень абстракции.

func (s *CommandHandler) beginTransaction() {
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

func (s *CommandHandler) writeMessage() {
	_, err := s.writer().Write([]byte(s.message()))
	if err != nil {
		panic(err)
	}
}

func (s *CommandHandler) closeTransaction() {
	s.closeWriter()
	s.client().Quit()
}

// 2-й уровень абстракции.

func (s *CommandHandler) auth() smtp.Auth {
	return smtp.PlainAuth("", secrets.SENDER_USER_NAME, secrets.SENDER_PASSWORD, secrets.SMTP_SERVER_HOST)
}

func (s *CommandHandler) message() string {
	return strings.Join([]string{
		"From: " + secrets.SENDER_EMAIL,
		"To: " + s.Command.ReceiverEmail,
		"Subject: " + s.Command.MessageSubject,
		s.Command.MessageBody,
	}, "\r\n")
}

func (s *CommandHandler) closeWriter() {
	err := s.writer().Close()
	if err != nil {
		panic(err)
	}
}

// 3-й уровень абстракции.

func (s *CommandHandler) writer() io.WriteCloser {
	if s._writer == nil {
		s._writer = s.createWriter()
	}

	return s._writer
}

// 4-й уровень абстракции.

func (s *CommandHandler) createWriter() io.WriteCloser {
	writer, err := s.client().Data()
	if err != nil {
		panic(err)
	}

	return writer
}

// 5-й уровень абстракции.

func (s *CommandHandler) client() *smtp.Client {
	if s._client == nil {
		s._client = s.createClient()
	}

	return s._client
}

// 6-й уровень абстракции.

func (s *CommandHandler) createClient() *smtp.Client {
	client, err := smtp.NewClient(s.createConnection(), secrets.SMTP_SERVER_HOST)
	if err != nil {
		panic(err)
	}

	return client
}

// 7-й уровень абстракции.

func (s *CommandHandler) createConnection() *tls.Conn {
	connection, err := tls.Dial("tcp", secrets.SMTP_SERVER_ADDRESS, s.tlsConfig())
	if err != nil {
		panic(err)
	}

	return connection
}

// 8-й уровень абстракции.

func (s *CommandHandler) tlsConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         secrets.SMTP_SERVER_HOST,
	}
}
