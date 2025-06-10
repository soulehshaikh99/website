<?php
require './../vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
use Dotenv\Dotenv;
use Slim\App;

$dotenv = Dotenv::createImmutable(__DIR__ . '/../');
$dotenv->load();

$app = new App();

// Health check route
$app->get('/health', function ($request, $response, $args) {
    return $response->withJson([
        'success' => true, 
        'message' => date('jS F Y h:i:sA')
    ]);
});

// Fetch public key
$app->get('/getPublicKey', function ($request, $response, $args) {
    $publicKeyPath = __DIR__ . '/../data/public_key_2048.pem';

    if (!file_exists($publicKeyPath)) {
        error_log("ERROR: Public key file not found at $publicKeyPath");
        return $response->withStatus(500)->withJson([
            'success' => false,
            'message' => 'Public key not found.'
        ]);
    }

    $publicKey = file_get_contents($publicKeyPath);
    if (!$publicKey) {
        error_log("ERROR: Failed to read public key at $publicKeyPath");
        return $response->withStatus(500)->withJson([
            'success' => false,
            'message' => 'Failed to read public key.'
        ]);
    }

    return $response->withJson([
        'success' => true,
        'publicKey' => $publicKey
    ]);
});

// Contact form
$app->post('/contact', function ($request, $response, $args) {
    $privateKeyPath = __DIR__ . '/../admin/data/private_key_2048.pem';

    if (!file_exists($privateKeyPath)) {
        error_log("ERROR: Private key file not found at $privateKeyPath");
        return $response->withStatus(500)->withJson([
            'status' => 'error',
            'message' => 'Private key not found.'
        ]);
    }

    $privateKeyPem = file_get_contents($privateKeyPath);
    $privateKey = openssl_pkey_get_private($privateKeyPem);

    if (!$privateKey) {
        error_log("ERROR: Failed to load private key from $privateKeyPath");
        return $response->withStatus(500)->withJson([
            'status' => 'error',
            'message' => 'Failed to load private key.'
        ]);
    }

    $requestData = $request->getParsedBody();
    if (json_last_error() !== JSON_ERROR_NONE) {
        error_log("ERROR: Invalid JSON data received - " . json_last_error_msg());
        return $response->withStatus(400)->withJson([
            'status' => 'error',
            'message' => 'Invalid JSON data.'
        ]);
    }

    if (!isset($requestData['data'])) {
        error_log("Missing 'data' field in request.");
        return $response->withStatus(400)->withJson([
            'status' => 'error',
            'message' => "Missing 'data' field."
        ]);
    }

    $parts = explode('.', $requestData['data']);

    if (count($parts) !== 3) {
        error_log("Invalid data format, expected 3 parts but received " . count($parts));
        return $response->withStatus(400)->withJson([
            'status' => 'error',
            'message' => 'Invalid encrypted data format.'
        ]);
    }

    $encryptedPayload = $parts[0];
    $encryptedKey = $parts[1];
    $encryptedIv = $parts[2];

    $decryptedKey = '';
    $decryptedIv = '';
    $successKey = openssl_private_decrypt(base64_decode($encryptedKey), $decryptedKey, $privateKey, OPENSSL_PKCS1_OAEP_PADDING);
    $successIv = openssl_private_decrypt(base64_decode($encryptedIv), $decryptedIv, $privateKey, OPENSSL_PKCS1_OAEP_PADDING);

    if (!$successKey || !$successIv) {
        error_log("ERROR: Failed to decrypt AES key or IV.");
        return $response->withStatus(400)->withJson([
            'status' => 'error',
            'message' => 'Failed to decrypt AES key or IV.'
        ]);
    }

    $encryptedPayload = hex2bin($encryptedPayload);
    $decryptedPayload = openssl_decrypt($encryptedPayload, 'AES-256-CBC', $decryptedKey, OPENSSL_RAW_DATA, $decryptedIv);

    if ($decryptedPayload === false) {
        error_log("ERROR: Failed to decrypt payload.");
        return $response->withStatus(400)->withJson([
            'status' => 'error',
            'message' => 'Failed to decrypt payload.'
        ]);
    }

    $payload = json_decode($decryptedPayload, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        error_log("ERROR: Invalid JSON in decrypted payload - " . json_last_error_msg());
        return $response->withStatus(400)->withJson([
            'status' => 'error',
            'message' => 'Invalid JSON in decrypted payload.'
        ]);
    }

    $email = filter_var($payload['email'], FILTER_SANITIZE_EMAIL);
    $subject = htmlspecialchars($payload['subject']);
    $message = htmlspecialchars($payload['message']);

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        error_log("ERROR: Invalid email address provided: $email");
        return $response->withStatus(400)->withJson([
            'status' => 'error',
            'message' => 'Invalid email address.'
        ]);
    }

    $mail = new PHPMailer(true);

    try {
        $mail->isSMTP();
        $mail->Host = $_ENV['SMTP_HOST'];
        $mail->SMTPAuth = true;
        $mail->Username = $_ENV['SMTP_USERNAME'];
        $mail->Password = $_ENV['SMTP_PASSWORD'];
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = 587;

        $mail->setFrom($_ENV['SMTP_USERNAME'], $_ENV['WEBSITE_NAME']);
        $mail->addAddress($_ENV['SMTP_USERNAME']);
        $mail->addReplyTo($email);

        $mail->Subject = $subject;
        $mail->isHTML(false);
        $mail->Body = $message;

        $mail->send();

        return $response->withJson([
            'status' => 'success',
            'message' => 'Message email sent successfully.',
        ]);
    } catch (Exception $e) {
        error_log("ERROR: Mailer failed - " . $mail->ErrorInfo);
        return $response->withStatus(500)->withJson([
            'status' => 'error',
            'message' => 'Message could not be sent. Mailer Error: ' . $mail->ErrorInfo
        ]);
    }
});

$app->run();
