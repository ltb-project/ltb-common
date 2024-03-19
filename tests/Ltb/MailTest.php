<?php

require __DIR__ . '/../../vendor/autoload.php';

$GLOBALS['mail_priority'] = 3; // Options: null (default), 1 = High, 3 = Normal, 5 = low. When null, the header is not set at all.
$GLOBALS['mail_charset'] = 'utf-8';
$GLOBALS['mail_contenttype'] = 'text/plain';
$GLOBALS['mail_wordwrap'] = 0;
$GLOBALS['mail_sendmailpath'] = '/usr/sbin/sendmail';
$GLOBALS['mail_protocol'] = 'smtp';
$GLOBALS['mail_smtp_debug'] = 0;
$GLOBALS['mail_debug_format'] = 'error_log';
$GLOBALS['mail_smtp_host'] = '127.0.0.1';
$GLOBALS['mail_smtp_port'] = '25';
$GLOBALS['mail_smtp_secure'] = false;
$GLOBALS['mail_smtp_autotls'] = false;
$GLOBALS['mail_smtp_auth'] = false;
$GLOBALS['mail_smtp_user'] = '';
$GLOBALS['mail_smtp_pass'] = '';
$GLOBALS['mail_smtp_keepalive'] = false;
$GLOBALS['mail_smtp_options'] = array();
$GLOBALS['mail_smtp_timeout'] = 30;


final class MailTest extends \Mockery\Adapter\Phpunit\MockeryTestCase
{


    public function test_init_mailer(): void
    {
        
        $mailer = Ltb\Mail::init_mailer();

        $this->assertEquals($GLOBALS['mail_priority'], $mailer->Priority, "Error while setting mail_priority");
        $this->assertEquals($GLOBALS['mail_charset'], $mailer->CharSet, "Error while setting mail_charset");
        $this->assertEquals($GLOBALS['mail_contenttype'], $mailer->ContentType, "Error while setting mail_contenttype");
        $this->assertEquals($GLOBALS['mail_wordwrap'], $mailer->WordWrap, "Error while setting mail_wordwrap");
        $this->assertEquals($GLOBALS['mail_sendmailpath'], $mailer->Sendmail, "Error while setting mail_sendmailpath");
        $this->assertEquals($GLOBALS['mail_protocol'], $mailer->Mailer, "Error while setting mail_protocol");
        $this->assertEquals($GLOBALS['mail_smtp_debug'], $mailer->SMTPDebug, "Error while setting mail_smtp_debug");
        $this->assertEquals($GLOBALS['mail_debug_format'], $mailer->Debugoutput, "Error while setting mail_debug_format");
        $this->assertEquals($GLOBALS['mail_smtp_host'], $mailer->Host, "Error while setting mail_smtp_host");
        $this->assertEquals($GLOBALS['mail_smtp_port'], $mailer->Port, "Error while setting mail_smtp_port");
        $this->assertEquals($GLOBALS['mail_smtp_secure'], $mailer->SMTPSecure, "Error while setting mail_smtp_secure");
        $this->assertEquals($GLOBALS['mail_smtp_autotls'], $mailer->SMTPAutoTLS, "Error while setting mail_smtp_autotls");
        $this->assertEquals($GLOBALS['mail_smtp_auth'], $mailer->SMTPAuth, "Error while setting mail_smtp_auth");
        $this->assertEquals($GLOBALS['mail_smtp_user'], $mailer->Username, "Error while setting mail_smtp_user");
        $this->assertEquals($GLOBALS['mail_smtp_pass'], $mailer->Password, "Error while setting mail_smtp_pass");
        $this->assertEquals($GLOBALS['mail_smtp_keepalive'], $mailer->SMTPKeepAlive, "Error while setting mail_smtp_keepalive");
        $this->assertEquals($GLOBALS['mail_smtp_options'], $mailer->SMTPOptions, "Error while setting mail_smtp_options");
        $this->assertEquals($GLOBALS['mail_smtp_timeout'], $mailer->Timeout, "Error while setting mail_smtp_timeout");

    }

    public function test_send_mail(): void
    {

        $mail_from = "{mail_from}";
        $mail_from_name = "ltb admin sender";
        $mail_signature = "";
        $mail = ['{mail_to}','ltbadmin@domain.com'];
        $data = [
                  'mail_from' => 'ltbadminsender@example.com',
                  "login" => 'ltbtest',
                  "mail_to" => 'ltbtest@domain.com',
                  "password" => 'secret'
                ];
        $subject = 'Mail test to {login}';
        $body = 'Hello {login}, this is a mail test from {mail_from}. Your new password is {password}';

        $mailerMock = Mockery::mock('PHPMailer\PHPMailer\PHPMailer');

        $mailerMock->shouldreceive('clearAddresses')
                   ->andReturn(true);

        $mailerMock->shouldreceive('setFrom')
                   ->with('ltbadminsender@example.com', 'ltb admin sender')
                   ->andReturn(true);

        $mailerMock->shouldreceive('addReplyTo')
                   ->with('ltbadminsender@example.com', 'ltb admin sender')
                   ->andReturn(true);

        $mailerMock->shouldreceive('addAddress')
                   ->with(Mockery::anyOf('ltbtest@domain.com', 'ltbadmin@domain.com'))
                   ->andReturn(true);

        $mailerMock->shouldreceive('send')
                   ->andReturn(true);

        $result = Ltb\Mail::send_mail($mailerMock, $mail, $mail_from, $mail_from_name, $subject, $body, $data);

        $this->assertEquals('Mail test to ltbtest', $mailerMock->Subject, "Error while processing subject");
        $this->assertEquals('Hello ltbtest, this is a mail test from ltbadminsender@example.com. Your new password is secret', $mailerMock->Body, "Error while processing body");
    }

    public function test_send_mail_global(): void
    {

        $mail_from = "{mail_from}";
        $mail_from_name = "ltb admin sender";
        $mail_signature = "";
        $mail = ['{mail_to}','ltbadmin@domain.com'];
        $data = [
                  'mail_from' => 'ltbadminsender@example.com',
                  "login" => 'ltbtest',
                  "mail_to" => 'ltbtest@domain.com',
                  "password" => 'secret'
                ];
        $subject = 'Mail test to {login}';
        $body = 'Hello {login}, this is a mail test from {mail_from}. Your new password is {password}';

        $GLOBALS['mailer'] = Mockery::mock('PHPMailer\PHPMailer\PHPMailer');

        $GLOBALS['mailer']->shouldreceive('clearAddresses')
                   ->andReturn(true);

        $GLOBALS['mailer']->shouldreceive('setFrom')
                   ->with('ltbadminsender@example.com', 'ltb admin sender')
                   ->andReturn(true);

        $GLOBALS['mailer']->shouldreceive('addReplyTo')
                   ->with('ltbadminsender@example.com', 'ltb admin sender')
                   ->andReturn(true);

        $GLOBALS['mailer']->shouldreceive('addAddress')
                   ->with(Mockery::anyOf('ltbtest@domain.com', 'ltbadmin@domain.com'))
                   ->andReturn(true);

        $GLOBALS['mailer']->shouldreceive('send')
                   ->andReturn(true);

        $result = Ltb\Mail::send_mail_global($mail, $mail_from, $mail_from_name, $subject, $body, $data);

        $this->assertEquals('Mail test to ltbtest', $GLOBALS['mailer']->Subject, "Error while processing subject");
        $this->assertEquals('Hello ltbtest, this is a mail test from ltbadminsender@example.com. Your new password is secret', $GLOBALS['mailer']->Body, "Error while processing body");
    }

}
