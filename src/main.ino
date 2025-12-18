#include <WiFiS3.h>
#include <WiFiUdp.h>

#include <LSM6DSV16XSensor.h>

#include <SHA256.h>

#include "arduino_secrets.h"

static const unsigned long SAMPLE_INTERVAL_MS = 100;
static const unsigned long SEND_INTERVAL_MS = 1000;
static const uint16_t MAX_BUFFER_SAMPLES = 150;

static const unsigned long NTP_RESYNC_INTERVAL_MS = 10UL * 60UL * 1000UL;
static const unsigned long NTP_SYNC_TIMEOUT_MS = 1500;

static const int NTP_PACKET_SIZE = 48;
static const unsigned long SEVENTY_YEARS = 2208988800UL;

static const unsigned int NTP_LOCAL_PORT = 2390;
static IPAddress timeServer(162, 159, 200, 123);

static byte packetBuffer[NTP_PACKET_SIZE];
static WiFiUDP Udp;

static unsigned long baseEpoch = 0;
static unsigned long baseMillis = 0;
static unsigned long lastNtpSyncMillis = 0;

static char ssid[] = SECRET_SSID;
static char pass[] = SECRET_PASS;
static int wifiStatus = WL_IDLE_STATUS;

static LSM6DSV16XSensor sensor(&Wire1);
static int32_t accel[3];
static int32_t gyro[3];
static int32_t prevAccel[3];
static int32_t prevGyro[3];
static bool hasPrev = false;

struct Sample {
  uint64_t timestamp;
  int32_t deltaX;
  int32_t deltaY;
  int32_t deltaZ;
  int32_t gyroDeltaX;
  int32_t gyroDeltaY;
  int32_t gyroDeltaZ;
};

static Sample buffer[MAX_BUFFER_SAMPLES];
static uint16_t bufferHead = 0;
static uint16_t bufferCount = 0;
static unsigned long lastSampleMillis = 0;
static unsigned long lastSendMillis = 0;

static String deviceToken;
static WiFiClient rawClient;

static void printWifiStatus()
{
  Serial.print("SSID: ");
  Serial.println(WiFi.SSID());

  IPAddress ip = WiFi.localIP();
  Serial.print("IP Address: ");
  Serial.println(ip);

  long rssi = WiFi.RSSI();
  Serial.print("signal strength (RSSI):");
  Serial.print(rssi);
  Serial.println(" dBm");
}

static void connectWiFi()
{
  if (WiFi.status() == WL_NO_MODULE) {
    Serial.println("Communication with WiFi module failed!");
    while (true) {
      delay(1000);
    }
  }

  String fv = WiFi.firmwareVersion();
  if (fv < WIFI_FIRMWARE_LATEST_VERSION) {
    Serial.println("Please upgrade the firmware");
  }

  while (wifiStatus != WL_CONNECTED) {
    Serial.print("Attempting to connect to SSID: ");
    Serial.println(ssid);
    wifiStatus = WiFi.begin(ssid, pass);
    delay(10000);
  }

  Serial.println("Connected to WiFi");
  printWifiStatus();
}

static unsigned long sendNTPpacket(IPAddress &address)
{
  memset(packetBuffer, 0, NTP_PACKET_SIZE);
  packetBuffer[0] = 0b11100011;
  packetBuffer[1] = 0;
  packetBuffer[2] = 6;
  packetBuffer[3] = 0xEC;
  packetBuffer[12]  = 49;
  packetBuffer[13]  = 0x4E;
  packetBuffer[14]  = 49;
  packetBuffer[15]  = 52;

  Udp.beginPacket(address, 123);
  Udp.write(packetBuffer, NTP_PACKET_SIZE);
  Udp.endPacket();
  return 0;
}

static bool syncTimeWithNtp()
{
  sendNTPpacket(timeServer);

  unsigned long start = millis();
  while ((millis() - start) < NTP_SYNC_TIMEOUT_MS) {
    int packetSize = Udp.parsePacket();
    if (packetSize >= NTP_PACKET_SIZE) {
      Udp.read(packetBuffer, NTP_PACKET_SIZE);

      unsigned long highWord = word(packetBuffer[40], packetBuffer[41]);
      unsigned long lowWord = word(packetBuffer[42], packetBuffer[43]);
      unsigned long secsSince1900 = (highWord << 16) | lowWord;
      unsigned long epoch = secsSince1900 - SEVENTY_YEARS;

      baseEpoch = epoch;
      baseMillis = millis();
      lastNtpSyncMillis = baseMillis;

      Serial.print("NTP sync ok, epoch=");
      Serial.println(baseEpoch);
      return true;
    }
    delay(10);
  }

  Serial.println("NTP sync timeout");
  return false;
}

static unsigned long getEpochSeconds()
{
  if (baseEpoch == 0) {
    return 0;
  }
  unsigned long elapsed = (millis() - baseMillis) / 1000UL;
  return baseEpoch + elapsed;
}

static uint64_t getEpochMillis()
{
  if (baseEpoch == 0) {
    return 0;
  }

  const uint64_t baseEpochMs = (uint64_t)baseEpoch * 1000ULL;
  const uint64_t elapsedMs = (uint64_t)(millis() - baseMillis);
  return baseEpochMs + elapsedMs;
}

static String u64ToString(uint64_t v)
{
  if (v == 0) {
    return String("0");
  }

  char buf[21];
  uint8_t i = 0;
  while (v > 0 && i < sizeof(buf)) {
    buf[i++] = (char)('0' + (v % 10));
    v /= 10;
  }

  String out;
  out.reserve(i);
  while (i > 0) {
    out += buf[--i];
  }
  return out;
}

static size_t digitsU64(uint64_t v)
{
  size_t d = 1;
  while (v >= 10ULL) {
    v /= 10ULL;
    ++d;
  }
  return d;
}

static size_t digitsI32(int32_t v)
{
  int64_t x = (int64_t)v;
  size_t d = 0;
  if (x < 0) {
    d += 1;
    x = -x;
  }
  d += digitsU64((uint64_t)x);
  return d;
}

static String base64UrlEncode(const uint8_t *data, size_t len)
{
  static const char *table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  String out;
  out.reserve(((len + 2) / 3) * 4);

  for (size_t i = 0; i < len; i += 3) {
    uint32_t n = ((uint32_t)data[i]) << 16;
    if ((i + 1) < len) {
      n |= ((uint32_t)data[i + 1]) << 8;
    }
    if ((i + 2) < len) {
      n |= (uint32_t)data[i + 2];
    }

    out += table[(n >> 18) & 0x3F];
    out += table[(n >> 12) & 0x3F];
    if ((i + 1) < len) {
      out += table[(n >> 6) & 0x3F];
    } else {
      out += '=';
    }
    if ((i + 2) < len) {
      out += table[n & 0x3F];
    } else {
      out += '=';
    }
  }

  out.replace('+', '-');
  out.replace('/', '_');
  while (out.endsWith("=")) {
    out.remove(out.length() - 1);
  }

  return out;
}

static String base64UrlEncode(const String &s)
{
  return base64UrlEncode(reinterpret_cast<const uint8_t *>(s.c_str()), s.length());
}

static void hmacSha256(const String &data, const char *key, uint8_t out[32])
{
  SHA256 sha;
  const size_t keyLen = strlen(key);

  sha.resetHMAC(key, keyLen);
  sha.update(data.c_str(), data.length());
  sha.finalizeHMAC(key, keyLen, out, 32);
}

static int registerDevice()
{
  String body;
  body.reserve(200);
  body += "{\"machine_id\":";
  body += String(MACHINE_ID);
  body += "}";

  WiFiClient client;
  if (!client.connect(SERVER_IP, SERVER_PORT)) {
    Serial.println("HTTP connect failed");
    return 0;
  }

  client.print("POST /device_register HTTP/1.1\r\n");
  client.print("Host: ");
  client.print(SERVER_IP);
  client.print("\r\n");
  client.print("Content-Type: application/json\r\n");
  client.print("Connection: close\r\n");
  client.print("Content-Length: ");
  client.print(body.length());
  client.print("\r\n\r\n");
  client.print(body);

  unsigned long start = millis();
  while (client.connected() && !client.available() && (millis() - start) < 5000) {
    delay(10);
  }

  String statusLine = client.readStringUntil('\n');
  statusLine.trim();
  Serial.print("Register status: ");
  Serial.println(statusLine);

  bool ok = statusLine.startsWith("HTTP/1.1 200") || statusLine.startsWith("HTTP/1.0 200");

  String rest;
  rest.reserve(512);
  unsigned long deadline = millis() + 1500;
  while (millis() < deadline) {
    while (client.available()) {
      rest += (char)client.read();
      deadline = millis() + 150;
    }
    if (!client.connected()) {
      break;
    }
    delay(5);
  }

  client.stop();

  if (!ok) {
    return 0;
  }

  int keyPos = rest.indexOf("\"token\"");
  if (keyPos < 0) {
    Serial.println("Register response missing token");
    return 0;
  }
  int colonPos = rest.indexOf(':', keyPos);
  if (colonPos < 0) {
    return 0;
  }
  int firstQuote = rest.indexOf('"', colonPos);
  if (firstQuote < 0) {
    return 0;
  }
  int secondQuote = rest.indexOf('"', firstQuote + 1);
  if (secondQuote < 0) {
    return 0;
  }

  deviceToken = rest.substring(firstQuote + 1, secondQuote);
  if (deviceToken.length() < 10) {
    Serial.println("Register token parse failed");
    deviceToken = "";
    return 0;
  }

  Serial.print("Device token length: ");
  Serial.println(deviceToken.length());
  return 1;
}

static String makeDeviceJwt()
{
  const String header = base64UrlEncode(String("{\"alg\":\"HS256\",\"typ\":\"JWT\"}"));

  const unsigned long now = getEpochSeconds();
  const String payload =
    String("{\"sub\":\"") + String(MACHINE_ID) + String("\",\"iat\":") + String(now) + String("}");

  const String payloadEnc = base64UrlEncode(payload);
  const String signingInput = header + "." + payloadEnc;

  uint8_t mac[32];
  hmacSha256(signingInput, DEVICE_SECRET_KEY, mac);

  const String sig = base64UrlEncode(mac, sizeof(mac));
  return signingInput + "." + sig;
}

static bool ensureRawClientConnected()
{
  if (rawClient.connected()) {
    return true;
  }

  rawClient.stop();
  if (!rawClient.connect(SERVER_IP, SERVER_PORT)) {
    return false;
  }

  rawClient.setTimeout(1500);
  return true;
}

static bool readAndDrainHttpResponse(WiFiClient &client, bool &ok, bool &shouldClose)
{
  ok = false;
  shouldClose = false;

  unsigned long start = millis();
  while (client.connected() && !client.available()) {
    if ((millis() - start) >= 5000) {
      Serial.println("HTTP response timeout");
      shouldClose = true;
      return false;
    }
    delay(10);
  }

  if (!client.available()) {
    Serial.println("HTTP response missing");
    shouldClose = true;
    return false;
  }

  String statusLine = client.readStringUntil('\n');
  statusLine.trim();
  Serial.print("HTTP status: ");
  Serial.println(statusLine);

  ok = statusLine.startsWith("HTTP/1.1 200") || statusLine.startsWith("HTTP/1.0 200");

  int32_t responseLength = -1;
  bool chunked = false;

  while (true) {
    String line = client.readStringUntil('\n');
    line.trim();
    if (line.length() == 0) {
      break;
    }

    if (line.startsWith("Content-Length:") || line.startsWith("content-length:")) {
      const int colon = line.indexOf(':');
      if (colon >= 0) {
        responseLength = (int32_t)line.substring(colon + 1).toInt();
      }
    }

    if (line.startsWith("Transfer-Encoding:") || line.startsWith("transfer-encoding:")) {
      if (line.indexOf("chunked") >= 0) {
        chunked = true;
      }
    }

    if (line.startsWith("Connection:") || line.startsWith("connection:")) {
      if (line.indexOf("close") >= 0) {
        shouldClose = true;
      }
    }
  }

  size_t printed = 0;
  const bool printBody = !ok;

  if (chunked) {
    while (true) {
      String sizeLine = client.readStringUntil('\n');
      sizeLine.trim();
      const long chunkSize = strtol(sizeLine.c_str(), nullptr, 16);
      if (chunkSize <= 0) {
        while (true) {
          String trailer = client.readStringUntil('\n');
          trailer.trim();
          if (trailer.length() == 0) {
            break;
          }
        }
        break;
      }

      for (long i = 0; i < chunkSize; ++i) {
        unsigned long dl = millis() + 1500;
        while (!client.available() && client.connected() && millis() < dl) {
          delay(1);
        }
        if (!client.available()) {
          shouldClose = true;
          break;
        }

        const char c = (char)client.read();
        if (printBody && printed < 512) {
          Serial.write(c);
        }
        ++printed;
      }

      unsigned long dl = millis() + 1500;
      while (!client.available() && client.connected() && millis() < dl) {
        delay(1);
      }
      if (client.available()) {
        client.read();
      }
      dl = millis() + 1500;
      while (!client.available() && client.connected() && millis() < dl) {
        delay(1);
      }
      if (client.available()) {
        client.read();
      }
    }
  } else if (responseLength >= 0) {
    for (int32_t i = 0; i < responseLength; ++i) {
      unsigned long dl = millis() + 1500;
      while (!client.available() && client.connected() && millis() < dl) {
        delay(1);
      }
      if (!client.available()) {
        shouldClose = true;
        break;
      }

      const char c = (char)client.read();
      if (printBody && printed < 512) {
        Serial.write(c);
      }
      ++printed;
    }
  } else {
    unsigned long deadline = millis() + 500;
    while (millis() < deadline) {
      while (client.available()) {
        const char c = (char)client.read();
        if (printBody && printed < 512) {
          Serial.write(c);
        }
        ++printed;
        deadline = millis() + 50;
      }
      if (!client.connected()) {
        break;
      }
      delay(5);
    }

    if (client.connected()) {
      shouldClose = true;
    }
  }

  if (!ok) {
    Serial.println();
  }

  return true;
}

static bool postRawDataBatch()
{
  if (deviceToken.length() == 0) {
    Serial.println("Missing device token");
    return false;
  }

  if (bufferCount == 0) {
    return true;
  }

  const uint64_t t0 = buffer[bufferHead].timestamp;
  const int32_t dt = (int32_t)SAMPLE_INTERVAL_MS;

  const size_t tokenLen = (size_t)deviceToken.length();
  size_t contentLength = 0;

  contentLength += strlen("{\"machine_id\":");
  contentLength += digitsI32((int32_t)MACHINE_ID);
  contentLength += strlen(",\"secret_key\":\"");
  contentLength += tokenLen;
  contentLength += strlen("\",\"t0\":");
  contentLength += digitsU64(t0);
  contentLength += strlen(",\"dt\":");
  contentLength += digitsI32(dt);
  contentLength += strlen(",\"samples\":[");

  for (uint16_t i = 0; i < bufferCount; ++i) {
    if (i > 0) {
      contentLength += 1;
    }

    const uint16_t idx = (uint16_t)((bufferHead + i) % MAX_BUFFER_SAMPLES);
    contentLength += 1;
    contentLength += digitsI32(buffer[idx].deltaX);
    contentLength += 1;
    contentLength += digitsI32(buffer[idx].deltaY);
    contentLength += 1;
    contentLength += digitsI32(buffer[idx].deltaZ);
    contentLength += 1;
    contentLength += digitsI32(buffer[idx].gyroDeltaX);
    contentLength += 1;
    contentLength += digitsI32(buffer[idx].gyroDeltaY);
    contentLength += 1;
    contentLength += digitsI32(buffer[idx].gyroDeltaZ);
    contentLength += 1;
  }

  contentLength += 2;

  if (!ensureRawClientConnected()) {
    Serial.println("HTTP connect failed");
    return false;
  }

  rawClient.print("POST /raw_data_compact HTTP/1.1\r\n");
  rawClient.print("Host: ");
  rawClient.print(SERVER_IP);
  rawClient.print("\r\n");
  rawClient.print("Content-Type: application/json\r\n");
  rawClient.print("Connection: keep-alive\r\n");
  rawClient.print("Content-Length: ");
  rawClient.print(contentLength);
  rawClient.print("\r\n\r\n");

  rawClient.print("{\"machine_id\":");
  rawClient.print(MACHINE_ID);
  rawClient.print(",\"secret_key\":\"");
  rawClient.print(deviceToken);
  rawClient.print("\",\"t0\":");
  rawClient.print(u64ToString(t0));
  rawClient.print(",\"dt\":");
  rawClient.print(dt);
  rawClient.print(",\"samples\":[");

  for (uint16_t i = 0; i < bufferCount; ++i) {
    if (i > 0) {
      rawClient.print(',');
    }

    const uint16_t idx = (uint16_t)((bufferHead + i) % MAX_BUFFER_SAMPLES);
    rawClient.print('[');
    rawClient.print(buffer[idx].deltaX);
    rawClient.print(',');
    rawClient.print(buffer[idx].deltaY);
    rawClient.print(',');
    rawClient.print(buffer[idx].deltaZ);
    rawClient.print(',');
    rawClient.print(buffer[idx].gyroDeltaX);
    rawClient.print(',');
    rawClient.print(buffer[idx].gyroDeltaY);
    rawClient.print(',');
    rawClient.print(buffer[idx].gyroDeltaZ);
    rawClient.print(']');
  }

  rawClient.print("]}");

  bool ok = false;
  bool shouldClose = false;
  if (!readAndDrainHttpResponse(rawClient, ok, shouldClose)) {
    rawClient.stop();
    return false;
  }

  if (!ok) {
    rawClient.stop();
    return false;
  }

  if (shouldClose) {
    rawClient.stop();
  }

  bufferHead = 0;
  bufferCount = 0;
  return true;
}

static void initSensor()
{
  Wire1.begin();
  sensor.begin();
  sensor.Enable_X();
  sensor.Enable_G();

  Serial.println("Sensor initialized");
}

static void collectSample()
{
  sensor.Get_X_Axes(accel);
  sensor.Get_G_Axes(gyro);

  Sample s;
  s.timestamp = getEpochMillis();

  if (!hasPrev) {
    s.deltaX = 0;
    s.deltaY = 0;
    s.deltaZ = 0;
    s.gyroDeltaX = 0;
    s.gyroDeltaY = 0;
    s.gyroDeltaZ = 0;
    hasPrev = true;
  } else {
    s.deltaX = accel[0] - prevAccel[0];
    s.deltaY = accel[1] - prevAccel[1];
    s.deltaZ = accel[2] - prevAccel[2];
    s.gyroDeltaX = gyro[0] - prevGyro[0];
    s.gyroDeltaY = gyro[1] - prevGyro[1];
    s.gyroDeltaZ = gyro[2] - prevGyro[2];
  }

  prevAccel[0] = accel[0];
  prevAccel[1] = accel[1];
  prevAccel[2] = accel[2];

  prevGyro[0] = gyro[0];
  prevGyro[1] = gyro[1];
  prevGyro[2] = gyro[2];

  if (bufferCount < MAX_BUFFER_SAMPLES) {
    const uint16_t idx = (uint16_t)((bufferHead + bufferCount) % MAX_BUFFER_SAMPLES);
    buffer[idx] = s;
    ++bufferCount;
    return;
  }

  buffer[bufferHead] = s;
  bufferHead = (uint16_t)((bufferHead + 1) % MAX_BUFFER_SAMPLES);
}

void setup()
{
  Serial.begin(115200);
  while (!Serial) {
    delay(10);
  }

  connectWiFi();

  while (true) {
    int r = registerDevice();
    if (r > 0) {
      break;
    }
    if (r < 0) {
      Serial.println("Device register unauthorized (secret mismatch)");
      while (true) {
        delay(1000);
      }
    }
    Serial.println("Device register failed; retrying");
    delay(2000);
  }

  Udp.begin(NTP_LOCAL_PORT);
  syncTimeWithNtp();

  initSensor();

  lastSampleMillis = millis();
  lastSendMillis = lastSampleMillis;
}

void loop()
{
  if (WiFi.status() != WL_CONNECTED) {
    wifiStatus = WL_IDLE_STATUS;
    connectWiFi();
  }

  if (baseEpoch == 0 || (millis() - lastNtpSyncMillis) > NTP_RESYNC_INTERVAL_MS) {
    syncTimeWithNtp();
  }

  const unsigned long nowMs = millis();
  while ((nowMs - lastSampleMillis) >= SAMPLE_INTERVAL_MS) {
    lastSampleMillis += SAMPLE_INTERVAL_MS;
    collectSample();
  }

  if (bufferCount > 0 && ((nowMs - lastSendMillis) >= SEND_INTERVAL_MS || bufferCount >= MAX_BUFFER_SAMPLES)) {
    Serial.println("Sending raw_data batch...");
    if (postRawDataBatch()) {
      Serial.println("Batch sent OK");
      lastSendMillis = nowMs;
    } else {
      Serial.println("Batch send failed; will retry");
      delay(1000);
    }
  }
}
