#include <SPI.h>
#include <MFRC522.h>

byte NEW_UID[4] = {0xFF, 0xFF, 0xFF, 0xFF};

#define RST_PIN         9
#define SS_PIN          10
MFRC522 mfrc522(SS_PIN, RST_PIN);
MFRC522::MIFARE_Key key;

void setup() {
  Serial.begin(9600);
  while (!Serial);
  SPI.begin();
  mfrc522.PCD_Init();

  for (byte i = 0; i < 6; i++) {
    key.keyByte[i] = 0xFF;
  }

  Serial.println(F("Scan card to read the original ID and then write the new ID (process will reset automatically)"));
  Serial.println();

}

void(* resetFunc) (void) = 0;

void loop() {
  
  MFRC522::StatusCode status;
  // auto reset
  if ( millis()  >= 10*1000UL ) resetFunc();

  if ( ! mfrc522.PICC_IsNewCardPresent())
    return;

  if ( ! mfrc522.PICC_ReadCardSerial())
    return;

  Serial.print(F("Current Card UID:"));
  dump_byte_array(mfrc522.uid.uidByte, mfrc522.uid.size);
  Serial.println();
  Serial.print(F("Current Card Type: "));
  MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
  Serial.println(mfrc522.PICC_GetTypeName(piccType));

  if (    piccType != MFRC522::PICC_TYPE_MIFARE_MINI
          &&  piccType != MFRC522::PICC_TYPE_MIFARE_1K
          &&  piccType != MFRC522::PICC_TYPE_MIFARE_4K) {
    Serial.println(F("Sorry~ Only Mifare Classic Card is accepted!!!"));
    return;
  }

  byte sector         = 0;
  byte blockAddr      = 0;
  dump_byte_array(NEW_UID, 4);
  Serial.println();

  byte validVal = NEW_UID[0] ^ NEW_UID[1] ^ NEW_UID[2] ^ NEW_UID[3];
  byte dataBlock[5];
  for (int i=0; i < 4; i++) {
    dataBlock[i] = NEW_UID[i];
  }
  dataBlock[4] = validVal;
  dump_byte_array(dataBlock, 5);
  byte trailerBlock = 1;
 
  byte buffer[18];
  byte size = sizeof(buffer);

  Serial.println(F("\n\nDisplaying original ID ..."));
  status = (MFRC522::StatusCode) mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Authentication failed."));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }

  // Read original ID
  Serial.print(F("Reading original ID ..."));
  status = (MFRC522::StatusCode) mfrc522.MIFARE_Read(blockAddr, buffer, &size);
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Card reading failed, disconnected."));
    Serial.println(mfrc522.GetStatusCodeName(status));
  }
  Serial.print(F("Original ID: "));
  dump_byte_array(buffer, mfrc522.uid.size); Serial.println();
  Serial.println();

  // Start writing
  Serial.println(F("Writing new ID ..."));
  status = (MFRC522::StatusCode) mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_B, trailerBlock, &key, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Card writing failed. Disconnected or access denied."));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }

  // Write data to the block
  dump_byte_array(dataBlock, mfrc522.uid.size); Serial.println(); // Print new ID to be written
  status = (MFRC522::StatusCode) mfrc522.MIFARE_Write(blockAddr, dataBlock, 16);
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Writing failed!"));
    Serial.println(mfrc522.GetStatusCodeName(status));
  }
  Serial.println();

  Serial.println(F("Rechecking ID after writing ..."));
  status = (MFRC522::StatusCode) mfrc522.MIFARE_Read(blockAddr, buffer, &size);
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Card reading failed!"));
    Serial.println(mfrc522.GetStatusCodeName(status));
  }
  Serial.print(F("Current ID: "));
  dump_byte_array(buffer, mfrc522.uid.size);
  Serial.println();

  // Validate writtein ID
  Serial.println(F("Validating written ID ..."));
  byte count = 0;
  for (byte i = 0; i < 16; i++) {
    if (buffer[i] == dataBlock[i])
      count++;
  }
  if (count == 16) {
    Serial.println(F("Validation success!"));
  } else {
    Serial.println(F("Validation failed! Current ID is not the expected new ID."));
  }
  Serial.println();

  // Current ID after writing attempt
  // Serial.println(F("Current ID after writing attempt:"));
  // mfrc522.PICC_DumpMifareClassicSectorToSerial(&(mfrc522.uid), &key, sector);
  // Serial.println();

  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();

  delay(2000);
}

// Additional procedure
void dump_byte_array(byte *buffer, byte bufferSize) {
  for (byte i = 0; i < bufferSize; i++) {
    Serial.print(buffer[i] < 0x10 ? " 0" : " ");
    Serial.print(buffer[i], HEX);
  }
}