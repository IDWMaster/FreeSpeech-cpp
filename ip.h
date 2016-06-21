/*

 This file is part of the GlobalGrid Protocol Suite.

    GlobalGrid is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    GlobalGrid is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with GlobalGrid.  If not, see <http://www.gnu.org/licenses/>.
 * */

#ifndef GG_IP
#define GG_IP
#include "GlobalGrid.h"
#include "cppext/cppext.h"
namespace IPProto {

class IIPDriver:public GlobalGrid::ProtocolDriver {
public:
  virtual ~IIPDriver(){};
  virtual std::shared_ptr<GlobalGrid::VSocket> MakeSocket(const System::Net::IPEndpoint& ep) = 0;
  virtual void GetEP(System::Net::IPEndpoint& ep) = 0;
};
std::shared_ptr<IPProto::IIPDriver> CreateDriver(void* connectionManager, const System::Net::IPEndpoint& ep); 



}

#endif