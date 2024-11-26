#include <WiFi.h>
#include <PubSubClient.h>
#include <WiFiClientSecure.h>

// Configurações Wi-Fi
const char* ssid = "O nome da sua rede";
const char* password = "A senha da sua rede";

// Configurações MQTT
// Configurações do broker MQTT
const char* mqtt_server = "Broker MQTT";
const char* mqtt_username = "Username MQTT";
const char* mqtt_password = "Password_MQTT";
const int mqtt_port = PORT MQTT;

// Tópicos MQTT (ajustados dinamicamente com user_id)
int user_id = SEU ID;  // Substitua por ID correspondente
String topic_command = "home/" + String(user_id) + "/esp32/leds";
String topic_status = "home/" + String(user_id) + "/esp32/status";

// Pinos dos LEDs
const int ledPins[] = {2, 4, 16, 17};
int ledStates[] = {0, 0, 0, 0};  // Estados iniciais dos LEDs

// Pinos dos botões
const int buttonPins[] = {18, 19, 21, 22};
int buttonStates[] = {0, 0, 0, 0};
int lastButtonStates[] = {1, 1, 1, 1};

// Debounce
unsigned long debounceDelay = 50;
unsigned long lastDebounceTime[] = {0, 0, 0, 0};

// WiFi e MQTT
WiFiClientSecure espClient;
PubSubClient client(espClient);

void setup() {
  Serial.begin(115200);

  // Configurações de Wi-Fi
  setupWiFi();

  // Configuração do cliente MQTT
  espClient.setInsecure(); // TLS sem validação de certificado
  client.setServer(mqtt_server, mqtt_port);
  client.setCallback(callback);

  // Configuração dos LEDs
  for (int i = 0; i < 4; i++) {
    pinMode(ledPins[i], OUTPUT);
    digitalWrite(ledPins[i], LOW); // LEDs iniciam desligados
  }

  // Configuração dos botões
  for (int i = 0; i < 4; i++) {
    pinMode(buttonPins[i], INPUT_PULLUP); // Botões com resistor pull-up interno
  }
}

void loop() {
  if (!client.connected()) {
    reconnect();
  }
  client.loop();

  // Verifica o estado dos botões
  for (int i = 0; i < 4; i++) {
    int currentState = digitalRead(buttonPins[i]);

    // Detecta mudanças de estado com debounce
    if (currentState != lastButtonStates[i]) {
      lastDebounceTime[i] = millis();
    }

    if ((millis() - lastDebounceTime[i]) > debounceDelay) {
      if (currentState != buttonStates[i]) {
        buttonStates[i] = currentState;

        // Quando o botão é pressionado (LOW)
        if (buttonStates[i] == LOW) {
          toggleLED(i); // Altera o estado do LED correspondente
          publishLEDState(i); // Publica o novo estado no MQTT
        }
      }
    }

    lastButtonStates[i] = currentState;
  }
}

// Configuração Wi-Fi
void setupWiFi() {
  delay(10);
  Serial.println("Conectando ao Wi-Fi...");
  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("\nWi-Fi conectado!");
  Serial.print("Endereço IP: ");
  Serial.println(WiFi.localIP());
}

// Reconexão ao MQTT
void reconnect() {
  while (!client.connected()) {
    Serial.print("Tentando conectar ao MQTT...");
    if (client.connect("ESP32Client", mqtt_user, mqtt_password)) {
      Serial.println("Conectado!");
      client.subscribe(topic_command.c_str()); // Inscrição no tópico de comandos
    } else {
      Serial.print("Falha, rc=");
      Serial.print(client.state());
      Serial.println(" Tentando novamente em 5 segundos...");
      delay(5000);
    }
  }
}

// Callback para mensagens MQTT
void callback(char* topic, byte* payload, unsigned int length) {
  char message[length + 1];
  strncpy(message, (char*)payload, length);
  message[length] = '\0';

  String msgString = String(message);
  int delimiterIndex = msgString.indexOf(':');
  String ledStr = msgString.substring(0, delimiterIndex);
  String stateStr = msgString.substring(delimiterIndex + 1);

  int ledIndex = ledStr.substring(3).toInt() - 1; // Extrai o índice do LED
  int state = stateStr.toInt();

  if (ledIndex >= 0 && ledIndex < 4) {
    ledStates[ledIndex] = state;
    digitalWrite(ledPins[ledIndex], state == 1 ? HIGH : LOW);

    Serial.print("Comando recebido: LED ");
    Serial.print(ledIndex + 1);
    Serial.print(" -> ");
    Serial.println(state == 1 ? "ON" : "OFF");

    // Publica o estado atualizado
    publishLEDState(ledIndex);
  }
}

// Alterna o estado de um LED
void toggleLED(int index) {
  ledStates[index] = !ledStates[index];
  digitalWrite(ledPins[index], ledStates[index] == 1 ? HIGH : LOW);
  Serial.print("LED ");
  Serial.print(index + 1);
  Serial.println(ledStates[index] ? " ON" : " OFF");
}

// Publica o estado do LED no MQTT
void publishLEDState(int index) {
  String message = "led" + String(index + 1) + ":" + String(ledStates[index]);
  client.publish(topic_status.c_str(), message.c_str());
  Serial.print("Estado publicado: ");
  Serial.println(message);
}
