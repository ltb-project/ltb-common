<?php

namespace Ltb;

require __DIR__ . '/../../vendor/autoload.php';

require __DIR__ . '/../../src/Ltb/Mail.php';

## Mail
# Who the email should come from
$mail_from = "admin@example.com";
$mail_from_name = "Ltb:Mail Test";
$mail_signature = "";

# PHPMailer configuration (see https://github.com/PHPMailer/PHPMailer)
$mail_sendmailpath = '/usr/sbin/sendmail';
$mail_protocol = 'smtp';
$mail_smtp_debug = 0;
$mail_debug_format = 'error_log';
#$mail_smtp_host = 'localhost';
$mail_smtp_host = '172.20.0.2';
$mail_smtp_auth = false;
$mail_smtp_user = '';
$mail_smtp_pass = '';
# $mail_smtp_port = 25;
$mail_smtp_port = 1025;
$mail_smtp_timeout = 30;
$mail_smtp_keepalive = false;
# $mail_smtp_secure = 'tls';
$mail_smtp_secure = false;
# $mail_smtp_autotls = true;
$mail_smtp_autotls = false;
$mail_smtp_options = array();
$mail_contenttype = 'text/plain';
$mail_wordwrap = 0;
$mail_charset = 'utf-8';
$mail_priority = 3;

$login='ltbtest';
$mail_to='ltbtest@dev.worteks.com';
$mail=array('{mail}','happy@dev.worteks.com');
$newpassword='!:/%%newpassword';

$data = array( "login" => $login, "mail" => $mail_to, "password" => $newpassword);

$messages['changesubject'] = "Votre mot de passe a été changé";
$messages['changemessage'] = "Bonjour {login},\n\nVotre mot de passe a été changé.\n\nSi vous n'êtes pas à l'origine de cette demande, contactez votre administrateur immédiatement. votre mail : {mail}";

Mail::send_mail_global($mail, $mail_from, $mail_from_name, $messages["changesubject"], $messages["changemessage"].$mail_signature, $data);
