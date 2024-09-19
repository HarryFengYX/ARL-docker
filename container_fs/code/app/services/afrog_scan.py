import json
import os.path
import subprocess

from app.config import Config
from app import utils


logger = utils.get_logger()


class AfrogScan(object):
    def __init__(self, targets: list):
        self.targets = targets

        tmp_path = Config.TMP_PATH
        rand_str = utils.random_choices()

        self.afrog_target_path = os.path.join(tmp_path,
                                               "afrog_target_{}.txt".format(rand_str))

        self.afrog_result_path = os.path.join(tmp_path,
                                               "afrog_result_{}.json".format(rand_str))

        self.afrog_bin_path = "/code/tools/afrog3.1.1"


    def _delete_file(self):
        try:
            os.unlink(self.afrog_target_path)
            # 删除结果临时文件
            if os.path.exists(self.afrog_result_path):
                os.unlink(self.afrog_result_path)
        except Exception as e:
            logger.warning(e)


    # check afrog
    def check_have_afrog(self) -> bool:
        command = [self.afrog_bin_path, "-version"]
        try:
            pro = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if pro.returncode == 0:
                return True
        except Exception as e:
            logger.debug("check_have_afrog failed: {}".format(str(e)))

        return False

    def _gen_target_file(self):
        with open(self.afrog_target_path, "w") as f:
            for domain in self.targets:
                domain = domain.strip()
                if not domain:
                    continue
                f.write(domain + "\n")

    def dump_result(self) -> list:
        results = []
        if os.path.exists(self.afrog_result_path):
            with open(self.afrog_result_path, "r") as f:
                datas = json.loads(f.read())
                for data in datas:
                    item = {
                        "pocresult": data.get("pocresult", ""),
                        "vuln_id": data.get("pocinfo", {}).get("id", ""),
                        "infoname": data.get("pocinfo", {}).get("infoname", ""),
                        "infoseg": data.get("pocinfo", {}).get("infoseg", ""),
                        "fulltarget": data.get("fulltarget", ""),
                        "target": data.get("target", "")
                    }
                    results.append(item)


        return results

    def exec_afrog(self):
        self._gen_target_file()

        command = [self.afrog_bin_path, "-doh",
                   "-T {}".format(self.afrog_target_path),
                   "-ja {}".format(self.afrog_result_path),
                   ]

        logger.info(" ".join(command))
        utils.exec_system(command, timeout=96*60*60)

    def run(self):
        logger.error("[hhhkb] afrog run")
        if not self.check_have_afrog():
            logger.warning("not found afrog")
            return []

        self.exec_afrog()

        results = self.dump_result()

        # 删除临时文件
        self._delete_file()

        return results


def afrog_scan(targets: list):
    if not targets:
        return []

    n = AfrogScan(targets=targets)
    print("test afrog")
    return n.run()

