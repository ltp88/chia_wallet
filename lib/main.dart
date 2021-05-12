import 'dart:convert';

import 'package:chia_wallet/bls.dart';
import 'package:convert/convert.dart';
import 'package:flutter/material.dart';

void main() {
  runApp(MyApp());
}

class MyApp extends StatelessWidget {
  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter Demo',
      theme: ThemeData(
        primarySwatch: Colors.blue,
      ),
      home: MyHomePage(title: 'Flutter Demo Home Page'),
    );
  }
}

class MyHomePage extends StatefulWidget {
  MyHomePage({Key key, this.title}) : super(key: key);

  final String title;

  @override
  _MyHomePageState createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  Bls _bls;
  List<int> _signature;
  String _privateKey;
  String _publicKey;
  String _message = "Hello world!";

  bool _verified;

  void _generate() {
    setState(() {
      //377091f0e728463bc2da7d546c53b9f6b81df4a1cc1ab5bf29c5908b7151a32d
      _bls = new Bls();
      _privateKey = _bls.privateKeyStr;
      _publicKey = _bls.publicKeyStr;
      _verified = false;

      final msg = utf8.encode(_message);
      _signature = _bls.sign(msg);

      _verified = _bls.verifySignature(_signature, msg);

    });
  }

  void _sign() {
    setState(() {


    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.title),
      ),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            FloatingActionButton.extended(
              onPressed: _generate,
              label: const Text("Gen Key & Sign"),
            ),
            Text(
              'Private Key: $_privateKey',
            ),
            Text(
              'Public Key: $_publicKey',
            ),
            Text(
              'Sign of \"$_message\" $_signature \n verified: $_verified',
            ),
          ],
        ),
      ),
    );
  }
}
