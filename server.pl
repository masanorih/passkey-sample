# server.pl (Perl, Mojolicious)
use Authen::WebAuthn;
use Crypt::URandom qw( urandom );
use MIME::Base64 qw( encode_base64url );
use JSON;
use MIME::Base64 'encode_base64url';
use Mojolicious::Lite;
use Mojolicious::Static;

my $rp = Authen::WebAuthn->new(
    rp_id  => "localhost",
    origin => "http://localhost:3000",
);

# 登録チャレンジ生成
post '/register/begin' => sub {
    my $c = shift;
    # FIXME challenge 生成に問題があるような気がしている。
    my $challenge = encode_base64url( urandom(10) );
    my $options = {
        rp => {
            name => "Example WebAuthn",
            id   => "localhost",
        },
        user => {
            id          => "AQIDBA",
            name        => "testUser",
            displayName => "testUser",
        },
        challenge => $challenge,
        pubKeyCredParams => [
            {type => "public-key", "alg" => -7},
            {type => "public-key", "alg" => -257},
        ],
        timeout => 20000,
        excludeCredentials => [],
        authenticatorSelection => {
            authenticatorAttachment => "platform",
            residentKey             => "preferred",
            requireResidentKey      => 0,
            userVerification        => "preferred"
        },
        attestation => "none",
        hints => ["client-device"],
    };
    # challenge=XwWjHkOR364NYQ
    warn "challenge=$challenge\n";
    $c->session->{challenge} = $challenge;
    $c->render(json => $options);
};

# 登録結果の検証
post '/register/finish' => sub {
    my $c = shift;
    my $data = $c->req->json;
    my $challenge = delete $c->session->{challenge};
    my $client_data = $data->{response}->{clientDataJSON};
    my $attestation = $data->{response}->{attestationObject};
    my $result = eval {
        $rp->validate_registration(
            challenge_b64          => $challenge,
            client_data_json_b64   => $client_data,
            attestation_object_b64 => $attestation,
        );
    };
    # validate_registration は検証失敗すると例外を返す
    return $c->render(json => {error => "Registration failed"}, status => 400)
        if $@;
    $c->session->{credential} = $result;
    $c->render(json => {status => "ok"});
};

# 認証チャレンジ生成
post '/authenticate/begin' => sub {
    my $c = shift;
    my $challenge = encode_base64url( urandom(10) );
    my $options = {
        challenge        => $challenge,
        timeout          => 20000,
        rpId             => "localhost",
        allowCredentials => [],
        userVerification => "preferred",
    };
    $c->session->{challenge} = $challenge;
    $c->render(json => $options);
};

# 認証結果の検証
post '/authenticate/finish' => sub {
    my $c = shift;
    my $data = $c->req->json;
    my $challenge = delete $c->session->{challenge};
    my $credential = $c->session->{credential};
    my $client_data = $data->{response}->{clientDataJSON};
    my $authentication = $data->{response}->{authenticatorData};
    my $signature = $data->{response}->{signature};
    my $result = eval {
        $rp->validate_assertion(
            challenge_b64          => $challenge,
            credential_pubkey_b64  => $credential->{credential_pubkey},
            client_data_json_b64   => $client_data,
            authenticator_data_b64 => $authentication,
            signature_b64          => $signature,
        );
    };
    return $c->render(json => {error => "Authentication failed"}, status => 400)
        if $@;
    $c->render(json => {status => "ok"});
};

app->start;
