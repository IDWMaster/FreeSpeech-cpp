#include "database.h"
#include "sqlite3.h"

#include <string.h>

#include <mutex>

static std::mutex mtx;

class Database {
public:
    sqlite3* db;
    sqlite3_stmt* getobj;
    sqlite3_stmt* findobj;
  Database() {
    sqlite3_open("freespeech_db",&db);
    const char* parsed;
    const char* stmt = "SELECT * FROM DHT WHERE ID = ?";
    sqlite3_prepare(db,stmt,strlen(stmt),&getobj,&parsed);
    stmt = "SELECT * FROM DHT WHERE Name = ? AND Parent = ?";
    sqlite3_prepare(db,stmt,strlen(stmt),&findobj,&parsed);
    
  }
};


static Database db;


void DB_ObjectLookup(const char* id,void* thisptr, void(*callback)(void*,const NamedObject&))
{
  std::unique_lock<std::mutex> l(mtx);
  sqlite3_bind_text(db.getobj,1,id,strlen(id),0);
  int val;
  while((val = sqlite3_step(db.getobj)) != SQLITE_DONE) {
   if(val == SQLITE_ROW) {
     NamedObject obj;
     obj.id = (char*)sqlite3_column_text(db.getobj,0);
     obj.owner = (char*)sqlite3_column_text(db.getobj,1);
     obj.name = (char*)sqlite3_column_text(db.getobj,2);
     obj.parent = (char*)sqlite3_column_text(db.getobj,3);
     obj.blob  = (unsigned char*)sqlite3_column_blob(db.getobj,4);
     obj.bloblen = sqlite3_column_bytes(db.getobj,5);
     callback(thisptr,obj);
     break;
   }
  }
}


void DB_FindByName(const char* name, const char* parentID,void* thisptr,void(*callback)(void*,const NamedObject&))
{
  std::unique_lock<std::mutex> l(mtx);
  sqlite3_bind_text(db.findobj,1,name,strlen(name),0);
  sqlite3_bind_text(db.findobj,2,parentID,strlen(parentID),0);
  
  
  
  int val;
  while((val = sqlite3_step(db.findobj)) != SQLITE_DONE) {
   if(val == SQLITE_ROW) {
     NamedObject obj;
     obj.id = (char*)sqlite3_column_text(db.findobj,0);
     obj.owner = (char*)sqlite3_column_text(db.findobj,1);
     obj.name = (char*)sqlite3_column_text(db.findobj,2);
     obj.parent = (char*)sqlite3_column_text(db.findobj,3);
     obj.blob  = (unsigned char*)sqlite3_column_blob(db.findobj,4);
     obj.bloblen = sqlite3_column_bytes(db.findobj,5);
     callback(thisptr,obj);
     break;
   }
  
}
}