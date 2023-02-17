<?php namespace Ltb;

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
use PHPMailer\PHPMailer\SMTP;

final class Mail {

    # Mail functions
    # rely on global mail configured with $mail_XXXX variables

    # init $mailer from config $mail_XXXX variables
    # legacy code to be compliant with self-service-password existing configuration
    static function init_mailer()
    {

        #==============================================================================
        # Email Config
        #==============================================================================

        global $mailer;
        global $mail_priority,  $mail_charset, $mail_contenttype,  $mail_wordwrap, $mail_sendmailpath;
        global $mail_protocol,  $mail_smtp_debug, $mail_debug_format, $mail_smtp_host, $mail_smtp_port;
        global $mail_smtp_secure, $mail_smtp_autotls, $mail_smtp_auth, $mail_smtp_user, $mail_smtp_pass;
        global $mail_smtp_keepalive, $mail_smtp_options, $mail_smtp_timeout;

        $mailer= new PHPMailer;

        $mailer->Priority      = $mail_priority;
        $mailer->CharSet       = $mail_charset;
        $mailer->ContentType   = $mail_contenttype;
        $mailer->WordWrap      = $mail_wordwrap;
        $mailer->Sendmail      = $mail_sendmailpath;
        $mailer->Mailer        = $mail_protocol;
        $mailer->SMTPDebug     = $mail_smtp_debug;
        $mailer->Debugoutput   = $mail_debug_format;
        $mailer->Host          = $mail_smtp_host;
        $mailer->Port          = $mail_smtp_port;
        $mailer->SMTPSecure    = $mail_smtp_secure;
        $mailer->SMTPAutoTLS   = $mail_smtp_autotls;
        $mailer->SMTPAuth      = $mail_smtp_auth;
        $mailer->Username      = $mail_smtp_user;
        $mailer->Password      = $mail_smtp_pass;
        $mailer->SMTPKeepAlive = $mail_smtp_keepalive;
        $mailer->SMTPOptions   = $mail_smtp_options;
        $mailer->Timeout       = $mail_smtp_timeout;

        return $mailer;
    }

    /* @function boolean send_mail_gloabl(PHPMailer $mailer, string $mail, string $mail_from, string $subject, string $body, array $data)
     * Send a mail, replace strings in body
     *
     * use global PHPMailer $mailer, create one from mail_XXX configurations if needed.
     #
     * @param mail Destination
     * @param mail_from Sender
     * @param subject Subject
     * @param body Body
     * @param data Data for string replacement
     * @return result
     */
    static function send_mail_global($mail, $mail_from, $mail_from_name, $subject, $body, $data) {
        global $mailer;
        if ( ! isset($mailer) )
        {
            \Ltb\Mail::init_mailer();
        }
        return \Ltb\Mail::send_mail($mailer, $mail, $mail_from, $mail_from_name, $subject, $body, $data);
    }

    /* @function boolean send_mail(PHPMailer $mailer, string $mail, string $mail_from, string $subject, string $body, array $data)
     * Send a mail, replace strings in body
     * @param mailer PHPMailer object
     * @param mail Destination
     * @param mail_from Sender
     * @param subject Subject
     * @param body Body
     * @param data Data for string replacement
     * @return result
     */
    static function send_mail($mailer, $mail, $mail_from, $mail_from_name, $subject, $body, $data) {

        $result = false;

        if (!is_a($mailer, 'PHPMailer\PHPMailer\PHPMailer')) {
            error_log("send_mail: PHPMailer object required!");
            return $result;
        }

        if (!$mail) {
            error_log("send_mail: no mail given, exiting...");
            return $result;
        }

        /* Replace data in mail, subject and body */
        foreach ($data as $key => $value ) {
            $mail = str_replace('{'.$key.'}', $value, $mail);
            $mail_from = str_replace('{'.$key.'}', $value, $mail_from);
            $subject = str_replace('{'.$key.'}', $value, $subject);
            $body = str_replace('{'.$key.'}', $value, $body);
        }

        $mailer->setFrom($mail_from, $mail_from_name);
        $mailer->addReplyTo($mail_from, $mail_from_name);
        $mailer->addAddress($mail);
        $mailer->Subject = $subject;
        $mailer->Body = $body;

        $result = $mailer->send();

        if (!$result) {
            error_log("send_mail: ".$mailer->ErrorInfo);
        }

        return $result;

    }

}
