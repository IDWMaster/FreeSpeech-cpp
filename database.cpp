#include "database.h"
#include "sqlite3.h"



class Database {
public:
    sqlite3* db;
  Database() {
    sqlite3_open("freespeech_db",&db);
  }
};


static Database db;