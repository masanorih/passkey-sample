from app.conf import conf
from flask import Flask, jsonify, request, render_template, session, redirect
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticationCredential,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialHint,
    RegistrationCredential,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
import json


app = Flask(__name__, static_url_path="")
app.config.from_mapping(conf)

# store registered user in memory.
users = {}
RP_ID = "localhost"
RP_NAME = "Example WebAuthn"
ORIGIN = "http://localhost:5000"


@app.route("/register/begin", methods=["POST"])
def register_begin():
    """
    rp_id:   対象となるドメイン
    rp_name: 表示用のサービス名
    user_id: サーバ側で一意に割り当てられるユニークユーザID(binary, base64)
    user_name,
    user_display_name: ユーザを識別するためのUI表示用の文字列
    resident_key:
        required:    必ず ResidentKey として Passkey を登録する
        preferred:   ResidentKey が使える認証器の場合は使う
        discouraged: Non-ResidentKey として Passkey を登録する

        required,preferred だとログイン時にユーザ名も不要となる
        discouraged だとユーザ名必須となる
    authenticator_attachment:
        platform:       デバイス内蔵認証(ブラウザだったらブラウザ内部完結)
        cross-platform: 外部デバイス認証(スマホ、USBキー等)
    attestation: 認証器の証明書チェイン(デバイスの製造元情報など)をどう扱うか？
        none:       デバイス情報をサーバに送らない
        direct:     認証器の証明書チェインが返却される
        indirect:   中間機関を通してデバイス検証を行う
        enterprise: 企業向けの特殊なユースケース。
                    クライアントが対応していないとエラーになる
    exclude_credentials:
        登録時に既に登録されている既存のクレデンシャルIDを返し、
        新規登録を制限する。
        FIXME 入れると動かないのでいったんコメントアウト。
    """
    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=bytes([1, 2, 3, 4]),
        user_name="testUser",
        user_display_name="testUser",
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.PREFERRED,
        ),
        challenge=bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
        exclude_credentials=[],
        # exclude_credentials=[
        #     PublicKeyCredentialDescriptor(id=b"1234567890"),
        # ],
        # pubKeyCredParams ES256=-7, RS256=-257
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        ],
        timeout=20000,
        hints=[PublicKeyCredentialHint.CLIENT_DEVICE],
    )

    j = request.get_json(silent=True)
    user_id = j.get("username")
    if not user_id:
        return jsonify({"error": "no username"}), 400
    session["user_id"] = user_id
    # challenge はランダムバイト列 16bytes 以上が推奨
    session["challenge"] = options.challenge
    return options_to_json(options)


@app.route("/register/finish", methods=["POST"])
def register_finish():
    user_id = session.get("user_id")
    challenge = session.get("challenge")
    if not user_id or not challenge:
        return jsonify({"error": "Session expired"}), 400
    credential = request.json
    try:
        # verify_registration_response は、例外を返さなければ成功
        verified_cred = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
        )
        users[user_id] = verified_cred
        return jsonify({"status": "Registration successful"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/authenticate/begin", methods=["POST"])
def begin_authenticate():
    user_id = session.get("user_id")
    if user_id not in users:
        return jsonify({"error": "User not registered"}), 400

    # user_verification:
    #     required:  ユーザ認証(chromeは PIN, edgeだと helloによる認証)が必須となる
    #     preferred: ユーザ認証は望ましいが必須ではない
    options = generate_authentication_options(
        rp_id=RP_ID,
        challenge=b"1234567890",
        timeout=12000,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    # register とは別の challenge
    session["challenge"] = options.challenge
    return options_to_json(options)


@app.route("/authenticate/finish", methods=["POST"])
def finish_authenticate():
    user_id = session.get("user_id")
    challenge = session.get("challenge")
    if not challenge:
        return jsonify({"error": "Session expired"}), 400

    credential = request.json
    try:
        verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=users[user_id].credential_public_key,
            credential_current_sign_count=users[user_id].sign_count,
        )
        return jsonify({"status": "Authentication successful"})
    except Exception as e:
        print(f"{e=}")
        return jsonify({"error": str(e)}), 400


# ユーザ登録情報を返す
@app.route("/users", methods=["GET"])
def getusers():
    ref = {}
    for user_id in users:
        r = users[user_id]
        pubkey = r.credential_public_key
        cnt = r.sign_count
        ref[user_id] = {"pubkey": str(pubkey), "sign_count": cnt}

    return ref
