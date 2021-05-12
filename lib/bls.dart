import 'dart:ffi'; // For FFI
import 'dart:io'; // For Platform.isX

import 'package:convert/convert.dart';
import 'package:ffi/ffi.dart';

typedef NativeGetPublicKeyFuncType = Pointer<Uint8> Function(Pointer<Uint8>);
typedef NativeSignFuncType = NativeByteArray Function(Pointer<Uint8>, NativeByteArray);
typedef NativeVerifyFuncType = Int8 Function(Pointer<Uint8>);

// library
final nativeLib =
    Platform.isAndroid ? DynamicLibrary.open("libsbl.so") : DynamicLibrary.process();

final nativeKeyGen = nativeLib
    .lookupFunction<Pointer<Uint8> Function(), Pointer<Uint8> Function()>("key_gen");

final nativeVerifySignature = nativeLib.lookupFunction<
    Uint8 Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>, Uint64),
    int Function(
        Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>, int)>("verify_signature");

// sign with private key & message
final nativeSign = nativeLib.lookupFunction<
    Pointer<Uint8> Function(Pointer<Uint8>, Pointer<Uint8>, Uint64),
    Pointer<Uint8> Function(Pointer<Uint8>, Pointer<Uint8>, int)>("sign");

// native get public key from private key
final NativeGetPublicKeyFuncType nativeGetPublicKey = nativeLib
    .lookup<NativeFunction<NativeGetPublicKeyFuncType>>("get_public_key")
    .asFunction();


// verify verify
final nativeVerify =
    nativeLib.lookupFunction<Int8 Function(Pointer<Uint8>), int Function(Pointer<Uint8>)>(
        "verify_key");

final nativeTestString = nativeLib
    .lookupFunction<Pointer<Utf8> Function(), Pointer<Utf8> Function()>("test_string");

const PRIVATE_KEY_LEN = 32;
const PUBLIC_KEY_LEN = 48;
const SIGNATURE_LEN = 96;

class NativeByteArray extends Struct {
  Pointer<Uint8> data;

  @Uint64()
  int size;
}

class Bls {
  List<int> _privateKey = [];
  List<int> _publicKey = [];

  Bls() {
    final data = nativeKeyGen().asTypedList(81);
    print(data);
    final success = data[0];
    if (success == 0) print("success");

    this._privateKey = data.sublist(1, 33);
    this._publicKey = data.sublist(33, 81);

    print(this._privateKey);
    print(this.privateKey);
    print(this._publicKey);
    print(this.publicKey);
  }

  Bls.fromPrivateKey(List<int> key) {
    this._privateKey = key;
    final Pointer<Uint8> pointer = calloc.allocate(_privateKey.length);
    final pointerList = pointer.asTypedList(_privateKey.length);
    pointerList.setAll(0, _privateKey);

    this._publicKey = nativeGetPublicKey(pointer).asTypedList(PUBLIC_KEY_LEN);
  }

  List<int> get privateKey {
    return _privateKey;
  }

  List<int> get publicKey {
    return _publicKey;
  }

  String get privateKeyStr {
    return hex.encode(_privateKey);
  }

  String get publicKeyStr {
    return hex.encode(_publicKey);
  }

  Pointer<Uint8> listToPointer(List<int> list) {
    final Pointer<Uint8> pointer = calloc.allocate(list.length);
    final pointerList = pointer.asTypedList(list.length);
    pointerList.setAll(0, list);
    return pointer;
  }

  List<int> sign(List<int> message) {
    print(message);
    final Pointer<Uint8> msg = listToPointer(message);
    final Pointer<Uint8> sk = listToPointer(this._privateKey);

    final sign = nativeSign(sk, msg, message.length);

    calloc.free(msg);
    calloc.free(sk);

    return sign.asTypedList(SIGNATURE_LEN);
  }

  bool verifySignature(List<int> signature, List<int> message) {
    final Pointer<Uint8> msg = listToPointer(message);
    final Pointer<Uint8> pk = listToPointer(this._publicKey);
    final Pointer<Uint8> s = listToPointer(signature);

    final ret = nativeVerifySignature(pk, s, msg, message.length);

    calloc.free(msg);
    calloc.free(pk);
    calloc.free(s);

    return ret == 0;
  }

  bool verify() {
    final Pointer<Uint8> sk = listToPointer(this._privateKey);
    final ret = nativeVerify(sk);

    calloc.free(sk);

    return ret == 0;
  }
}
