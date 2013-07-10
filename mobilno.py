import socket, struct, dbus, uuid
import os
import NetworkManager

class Connection:
	def GetInfo(self):
		print "-"*50
		print "Network manager info:"
		print("%-30s %s" % ("Version:", NetworkManager.NetworkManager.Version))
		print("%-30s %s" % ("Hostname:", NetworkManager.Settings.Hostname))
		print("%-30s %s" % ("Networking enabled:", NetworkManager.NetworkManager.NetworkingEnabled))
		print("%-30s %s" % ("Overall state:", NetworkManager.const('state', NetworkManager.NetworkManager.State)))
		print "\nAvailable connections:"
		print("%-30s %s" % ("Name", "Type"))
		for conn in NetworkManager.Settings.ListConnections():
			settings = conn.GetSettings()['connection']
			if settings['type'] == 'gsm':
				print("%-30s %s" % (settings['id'], settings['type']))
		print "\nActive connections:"
		print("%-30s %-20s %-10s %s" % ("Name", "Type", "Default", "Devices"))
		active_gsm = False
		for conn in NetworkManager.NetworkManager.ActiveConnections:
			settings = conn.Connection.GetSettings()['connection']
			if settings['type'] == 'gsm':
				print("%-30s %-20s %-10s %s" % (settings['id'], settings['type'], conn.Default, ", ".join([x.Interface for x in conn.Devices])))
				active_gsm = True
		if active_gsm == False:
			print "No gsm connections are active!"
				
		print "-"*50
		
	def SetDbusBoolean(self, value):
		if value == "Y":
			return dbus.Boolean(True)
		elif value == "N":
			return dbus.Boolean(False)
		print "\tInvalid input, set to False."
		return dbus.Boolean(False)
		
	def SetConnection(self):
		print "Global Settings: "
		param = dict()
		con_id = raw_input("\tConnection name: ")
		if con_id == '':
			con_id = "MyNetworkConnection"
		param['id'] = con_id
		con_uuid = str(uuid.uuid4())
		param['uuid'] = con_uuid
		print "\tuuid: ", con_uuid
		print "\tConnection type: GSM"
		con_auto = raw_input("\tAutoconnect [Y/N]: ")
		con_a = self.SetDbusBoolean(con_auto)
		param['autoconnect'] = con_a
		s_con_param = {}
		for key in param:
			if param[key] != '':
				s_con_param[key] = param[key]
		s_con_param['type'] = 'gsm'		
		
		s_con = dbus.Dictionary(s_con_param)
		
		print "PPP settings:"
		r_e = self.SetDbusBoolean(raw_input("\trefuse-eap [Y/N]: "))
		r_c = self.SetDbusBoolean(raw_input("\trefuse-chap [Y/N]: "))
		r_m = self.SetDbusBoolean(raw_input("\trefuse-mschap [Y/N]: "))
		r_m2 = self.SetDbusBoolean(raw_input("\trefuse-chap [Y/N]: "))
		
		s_ppp = dbus.Dictionary({
		'refuse-eap': r_e,
		'refuse-chap': r_c,
		'refuse-mschap': r_m,
		'refuse-mschapv2': r_m2})
		
		print "Mobile Broadband:"
		param = dict()
		number = '*99#'
		net_id = raw_input("\tNetwork id: ")
		param['netid'] = net_id
		number = raw_input("\tNumber [*99#]: ")
		if number == '':
			param['number'] = '*99#'
		else:
			param['number'] = number
		username = raw_input("\tUsername: ")
		param['username'] = username
		password = raw_input("\tPassword: ")
		param['password'] = password
		apn = raw_input("\tAPN:\n\t\t carnet.tele2.hr | carnet.vip.hr | mobileinternet.tele2.hr\n\t\t web.htgprs | data.vip.hr\n\t?:")
		param['apn'] = apn
		pin = raw_input("\tPIN: ")
		param['pin'] = pin
		g_gsm_param = dict()
		for key in param:
			if param[key] != '':
				g_gsm_param[key] = param[key]

		s_gsm = dbus.Dictionary(g_gsm_param)
		
		s_ip4 = dbus.Dictionary({'method': 'auto'})
		
		s_serial = dbus.Dictionary({'baud': dbus.UInt32(115200L)})
		
		print "Setting connection..."
		con = dbus.Dictionary({
		'connection': s_con,
		'ppp': s_ppp,
		'ipv4': s_ip4,
		'gsm': s_gsm,
		'serial': s_serial})
		
		return con
		
	def Connect(self, connection):
		bus = dbus.SystemBus()
		proxy = bus.get_object("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager/Settings")
		settings = dbus.Interface(proxy, "org.freedesktop.NetworkManager.Settings")
		settings.AddConnection(con)
		print "Connection added!"
		os.system("nm-connection-editor")
		
		
if __name__ == "__main__":
	connection = Connection()
	connection.GetInfo()
	con = connection.SetConnection()
	connection.Connect(con)
	
	
