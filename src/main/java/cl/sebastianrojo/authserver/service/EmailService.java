package cl.sebastianrojo.authserver.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import cl.sebastianrojo.authserver.config.properties.AuthProperties;
import cl.sebastianrojo.authserver.domain.entity.User;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;

/**
 * Servicio de envío de emails.
 *
 * <p>Los métodos son {@code @Async} para no bloquear el hilo principal
 * durante el envío. En dev, MailHog captura los emails en localhost:8025.</p>
 *
 * <p>En producción, configurar las credenciales SMTP en variables de entorno.</p>
 */
@Service
public class EmailService {

    private static final Logger log = LoggerFactory.getLogger(EmailService.class);

    private final JavaMailSender mailSender;
    private final AuthProperties authProperties;

    public EmailService(JavaMailSender mailSender, AuthProperties authProperties) {
        this.mailSender = mailSender;
        this.authProperties = authProperties;
    }

    /**
     * Envía el email de verificación de cuenta.
     */
    @Async
    public void sendVerificationEmail(User user, String token) {
        String verificationUrl = authProperties.email().baseUrl()
            + "/auth/verify-email?token=" + token;

        String subject = "Verifica tu cuenta en Auth Server";
        String html = buildVerificationEmailHtml(user.getFullName(), verificationUrl);

        sendHtmlEmail(user.getEmail(), subject, html);

        log.info("Email de verificación enviado a: {}", user.getEmail());
    }

    /**
     * Envía el email de recuperación de contraseña.
     */
    @Async
    public void sendPasswordResetEmail(User user, String token) {
        String resetUrl = authProperties.email().baseUrl()
            + "/reset-password?token=" + token;

        String subject = "Recuperación de contraseña — Auth Server";
        String html = buildPasswordResetEmailHtml(user.getFullName(), resetUrl);

        sendHtmlEmail(user.getEmail(), subject, html);

        log.info("Email de reset de contraseña enviado a: {}", user.getEmail());
    }

    // ── Privados ──────────────────────────────────────────────────────

    private void sendHtmlEmail(String to, String subject, String htmlContent) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(authProperties.email().from());
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(htmlContent, true);  // true = HTML

            mailSender.send(message);

        } catch (MessagingException ex) {
            log.error("Error al enviar email a {}: {}", to, ex.getMessage(), ex);
            // No propagar: el email fallido no debe romper el flujo de negocio.
            // En producción, considerar una cola de reintento (RabbitMQ/SQS).
        }
    }

    private String buildVerificationEmailHtml(String fullName, String verificationUrl) {
        String name = fullName != null ? fullName : "Usuario";
        return """
            <!DOCTYPE html>
            <html lang="es">
            <head><meta charset="UTF-8"></head>
            <body style="font-family: Arial, sans-serif; background: #f4f4f4; padding: 40px;">
              <div style="max-width: 600px; margin: 0 auto; background: white;
                          border-radius: 8px; padding: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <h1 style="color: #1a1a2e; margin-bottom: 8px;">Verifica tu cuenta</h1>
                <p style="color: #666; margin-bottom: 24px;">Hola %s,</p>
                <p style="color: #333; line-height: 1.6;">
                  Gracias por registrarte. Para completar tu registro,
                  haz clic en el botón a continuación para verificar tu email.
                </p>
                <div style="text-align: center; margin: 32px 0;">
                  <a href="%s"
                     style="background: #4f46e5; color: white; padding: 14px 32px;
                            border-radius: 6px; text-decoration: none; font-weight: bold;
                            display: inline-block;">
                    Verificar mi cuenta
                  </a>
                </div>
                <p style="color: #999; font-size: 14px;">
                  Este enlace expira en 24 horas. Si no creaste esta cuenta, ignora este email.
                </p>
                <p style="color: #ccc; font-size: 12px; margin-top: 32px; border-top: 1px solid #eee; padding-top: 16px;">
                  Si el botón no funciona, copia este enlace: <br>
                  <span style="color: #4f46e5;">%s</span>
                </p>
              </div>
            </body>
            </html>
            """.formatted(name, verificationUrl, verificationUrl);
    }

    private String buildPasswordResetEmailHtml(String fullName, String resetUrl) {
        String name = fullName != null ? fullName : "Usuario";
        return """
            <!DOCTYPE html>
            <html lang="es">
            <head><meta charset="UTF-8"></head>
            <body style="font-family: Arial, sans-serif; background: #f4f4f4; padding: 40px;">
              <div style="max-width: 600px; margin: 0 auto; background: white;
                          border-radius: 8px; padding: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <h1 style="color: #1a1a2e; margin-bottom: 8px;">Recuperar contraseña</h1>
                <p style="color: #666; margin-bottom: 24px;">Hola %s,</p>
                <p style="color: #333; line-height: 1.6;">
                  Recibimos una solicitud para restablecer la contraseña de tu cuenta.
                  Haz clic en el botón a continuación para crear una nueva contraseña.
                </p>
                <div style="text-align: center; margin: 32px 0;">
                  <a href="%s"
                     style="background: #dc2626; color: white; padding: 14px 32px;
                            border-radius: 6px; text-decoration: none; font-weight: bold;
                            display: inline-block;">
                    Restablecer contraseña
                  </a>
                </div>
                <p style="color: #999; font-size: 14px;">
                  ⚠️ Este enlace expira en 1 hora. Si no solicitaste este cambio,
                  ignora este email y tu contraseña permanecerá sin cambios.
                </p>
              </div>
            </body>
            </html>
            """.formatted(name, resetUrl);
    }
}