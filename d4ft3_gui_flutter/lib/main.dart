import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:share_plus/share_plus.dart';
import 'package:receive_sharing_intent/receive_sharing_intent.dart';
import 'package:d4ft3_ffi/d4ft3.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({Key? key}) : super(key: key);

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'D4FT File Transfer',
      theme: ThemeData(
        // This is the theme of your application.
        //
        // Try running your application with "flutter run". You'll see the
        // application has a blue toolbar. Then, without quitting the app, try
        // changing the primarySwatch below to Colors.green and then invoke
        // "hot reload" (press "r" in the console where you ran "flutter run",
        // or simply save your changes to "hot reload" in a Flutter IDE).
        // Notice that the counter didn't reset back to zero; the application
        // is not restarted.
        colorScheme: ColorScheme.dark(
          primary: Color.fromARGB(255, 244, 116, 4),
        ),
        fontFamily: 'JetBrains Mono',
      ),
      home: const MyHomePage(title: 'd4ft3'),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({Key? key, required this.title}) : super(key: key);

  // This widget is the home page of your application. It is stateful, meaning
  // that it has a State object (defined below) that contains fields that affect
  // how it looks.

  // This class is the configuration for the state. It holds the values (in this
  // case the title) provided by the parent (in this case the App widget) and
  // used by the build method of the State. Fields in a Widget subclass are
  // always marked "final".

  final String title;

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  late StreamSubscription _intentDataStreamSubscription;
  final _d4ft3 = D4ft3();
  final _textBoxController = TextEditingController();
  final _addressController = TextEditingController();
  final _logDisplayController = ScrollController();
  bool _connect = true;
  String _logText = '';

  void _addLogLine(String line) {
    setState(() {
      _logText += '$line\n';
    });
    _logDisplayController.animateTo(
      _logDisplayController.position.maxScrollExtent,
      duration: const Duration(milliseconds: 150),
      curve: Curves.easeOut,
    );
  }

  @override
  void initState() {
    super.initState();

    _intentDataStreamSubscription =
        ReceiveSharingIntent.getTextStream().listen((String value) {
          setState(() {
            _textBoxController.text = value;
          });
        }, onError: (err) {
          print("getLinkStream error: $err");
        });

    ReceiveSharingIntent.getInitialText().then((String? value) {
      setState(() {
        _textBoxController.text = value ?? '';
      });
    });
  }

  @override
  void dispose() {
    _intentDataStreamSubscription.cancel();
    _textBoxController.dispose();
    _addressController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    SystemChrome.setSystemUIOverlayStyle(SystemUiOverlayStyle.light.copyWith(
      systemNavigationBarColor: Theme.of(context).canvasColor,
    ));
    // This method is rerun every time setState is called, for instance as done
    // by the _incrementCounter method above.
    //
    // The Flutter framework has been optimized to make rerunning build methods
    // fast, so that you can just rebuild anything that needs updating rather
    // than having to individually change instances of widgets.
    return Scaffold(
      // appBar: AppBar(
      //   // Here we take the value from the MyHomePage object that was created by
      //   // the App.build method, and use it to set our appbar title.
      //   title: Text(widget.title),
      // ),
      body: Padding(
        padding: const EdgeInsets.fromLTRB(10, 50, 10, 5),
        // Center is a layout widget. It takes a single child and positions it
        // in the middle of the parent.
        child: Column(
          // Column is also a layout widget. It takes a list of children and
          // arranges them vertically. By default, it sizes itself to fit its
          // children horizontally, and tries to be as tall as its parent.
          //
          // Invoke "debug painting" (press "p" in the console, choose the
          // "Toggle Debug Paint" action from the Flutter Inspector in Android
          // Studio, or the "Toggle Debug Paint" command in Visual Studio Code)
          // to see the wireframe for each widget.
          //
          // Column has various properties to control how it sizes itself and
          // how it positions its children. Here we use mainAxisAlignment to
          // center the children vertically; the main axis here is the vertical
          // axis because Columns are vertical (the cross axis would be
          // horizontal).
          mainAxisAlignment: MainAxisAlignment.end,
          children: <Widget>[
            Expanded(child: Padding(
              padding: const EdgeInsets.all(0),
              child: Material(
                type: MaterialType.card,
                borderRadius: const BorderRadius.all(Radius.circular(10)),
                elevation: 5,
                child: Padding(
                  padding: const EdgeInsets.fromLTRB(10, 0, 10, 10),
                  child: TextField(
                    expands: true,
                    maxLines: null,
                    controller: _textBoxController,
                  ),
                ),
              ),
            )),
            Padding(
              padding: const EdgeInsets.only(top: 5),
              child: Row(
                children: [
                  Expanded(
                    child: Material(
                      type: MaterialType.card,
                      borderRadius: const BorderRadius.all(Radius.circular(10)),
                      elevation: 5,
                      child: Theme(
                        data: Theme.of(context).copyWith(
                          splashColor: Colors.transparent,
                          highlightColor: Colors.transparent,
                        ),
                        child: Padding(
                          padding: const EdgeInsets.fromLTRB(10, 0, 10, 0),
                          child: DropdownButton(
                            borderRadius: const BorderRadius.all(Radius.circular(10)),
                            underline: null,
                            isExpanded: true,
                            value: _connect,
                            onChanged: (bool? value) {
                              setState(() {
                                _connect = value!;
                              });
                            },
                            items: const [
                              DropdownMenuItem(
                                value: true,
                                child: Text('Connect'),
                              ),
                              DropdownMenuItem(
                                value: false,
                                child: Text('Listen'),
                              ),
                            ],
                          ),
                        ),
                      ),
                    ),
                  ),
                  Padding(
                    padding: const EdgeInsets.only(left: 5),
                    child: Material(
                      type: MaterialType.card,
                      borderRadius: BorderRadius.circular(10),
                      elevation: 5,
                      child: IconButton(
                        onPressed: () {
                          Clipboard.setData(ClipboardData(text: _textBoxController.text));
                        },
                        icon: const Icon(Icons.copy),
                      ),
                    ),
                  ),
                  Padding(
                    padding: const EdgeInsets.only(left: 5),
                    child: Material(
                      type: MaterialType.card,
                      borderRadius: BorderRadius.circular(10),
                      elevation: 5,
                      child: IconButton(
                        onPressed: () {
                          Share.share(_textBoxController.text);
                        },
                        icon: const Icon(Icons.share),
                      ),
                    ),
                  ),
                ],
              ),
            ),
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 5),
              child: Row(
                children: [
                  const Padding(
                    padding: EdgeInsets.all(5),
                    child: Text('Address:'),
                  ),
                  Expanded(child: Material(
                    type: MaterialType.card,
                    borderRadius: const BorderRadius.all(Radius.circular(10)),
                    elevation: 5,
                    child: Padding(
                      padding: const EdgeInsets.fromLTRB(10, 0, 10, 10),
                      child: TextField(
                        controller: _addressController,
                      ),
                    ),
                  )),
                ],
              ),
            ),
            SizedBox(
              width: double.infinity,
              height: 100,
              child: Material(
                type: MaterialType.card,
                borderRadius: const BorderRadius.all(Radius.circular(10)),
                child: Padding(
                  padding: const EdgeInsets.all(8.0),
                  child: ScrollConfiguration(
                    behavior: RemoveScrollGlow(),
                    child: SingleChildScrollView(
                      controller: _logDisplayController,
                      child: Text(
                        _logText,
                      ),
                    ),
                  ),
                ),
              ),
            ),
            Row(
              children: [
                Expanded(child: Padding(
                  padding: const EdgeInsets.only(right: 4),
                  child: ElevatedButton(
                    onPressed: () async {
                      _addLogLine(_connect ? 'connecting...' : 'listening...');
                      final result = await _d4ft3.sendTextAsync(
                        _textBoxController.text,
                        _addressController.text,
                        2581,
                        _connect,
                      );
                      _addLogLine(result);
                    },
                    child: const Text('SEND'),
                  ),
                )),
                Expanded(child: Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 2),
                  child: ElevatedButton(
                    onPressed: () async {
                      _addLogLine(_connect ? 'connecting...' : 'listening...');
                      final result = await _d4ft3.receiveTextAsync(
                        _addressController.text == '' ? '0.0.0.0' : _addressController.text,
                        2581,
                        _connect,
                      );
                      if (result.value != '') {
                        setState(() {
                          _textBoxController.text = result.value;
                        });
                      }
                      _addLogLine(result.message);
                    },
                    child: const Text('RECEIVE'),
                  ),
                )),
                Expanded(child: Padding(
                  padding: const EdgeInsets.only(left: 4),
                  child: ElevatedButton(
                    onPressed: () {
                      final result = _d4ft3.cancelTask();
                      _addLogLine(result);
                    },
                    child: const Text('CANCEL'),
                  ),
                ))
              ],
            ),
          ],
        ),
      ),
    );
  }
}

class RemoveScrollGlow extends ScrollBehavior {
  @override
  Widget buildOverscrollIndicator(
      BuildContext context, Widget child, ScrollableDetails details) {
    return child;
  }
}
