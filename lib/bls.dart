import 'dart:ffi'; // For FFI
import 'dart:io'; // For Platform.isX

typedef GenFuncType = NativeBlsKeyPair Function();

class NativeBlsKeyPair extends Struct {
  Pointer<Uint8> privateKey;
  Pointer<Uint8> publicKey;
}

final nativeLib =
    Platform.isAndroid ? DynamicLibrary.open("libsbl.so") : DynamicLibrary.process();

final GenFuncType nativeGenerateKeyPair =
    nativeLib.lookup<NativeFunction<GenFuncType>>("generate_key").asFunction();

class Bls {
  List<int> _privateKey;
  List<int> _publicKey;

  Bls() {
    NativeBlsKeyPair keyPair = nativeGenerateKeyPair();
    this._privateKey = keyPair.privateKey.asTypedList(32);
    this._publicKey = keyPair.privateKey.asTypedList(48);
  }

  Bls.fromPrivateKey(List<int> key) {
    this._privateKey = key;
  }

  List<int> get privateKey {
    return _privateKey;
  }

  List<int> get publicKey {
    return _publicKey;
  }


}
