from bson import ObjectId
from flask_restx import Resource, Api, reqparse, fields, Namespace
from app.utils import get_logger, auth
from . import base_query_fields, ARLResource, get_arl_parser
from app import utils
from app.modules import ErrorMsg

ns = Namespace('afrog_result', description="afrog 扫描结果")

logger = get_logger()

base_search_fields = {
    'pocresult': fields.String(required=False, description="请求包/返回包"),
    'vuln_id': fields.String(description="漏洞id"),
    'infoname': fields.String(description="漏洞名称"),
    'infoseg': fields.String(description="漏洞等级"),
    'fulltarget': fields.String(description="漏洞URL"),
    # 研究一下如何把 request 请求转换成 curl 命令
    # 'curl_command': fields.String(description="curl 命令"),
    # 有用，对应 target
    'target': fields.String(description="目标"),
    # 有用
    "task_id": fields.String(description="任务ID")
}

base_search_fields.update(base_query_fields)


@ns.route('/')
class ARLAfrog(ARLResource):
    parser = get_arl_parser(base_search_fields, location='args')

    @auth
    @ns.expect(parser)
    def get(self):
        """
        afrog 扫描结果查询
        """
        args = self.parser.parse_args()
        data = self.build_data(args=args, collection='afrog_result')

        return data

delete_afrog_result_fields = ns.model('deleteAfrogResultFields',  {
    '_id': fields.List(fields.String(required=True, description="afrog 扫描结果 _id"))
})


@ns.route('/delete/')
class DeleteAfrogResult(ARLResource):
    @auth
    @ns.expect(delete_afrog_result_fields)
    def post(self):
        """
        删除 nuclei 扫描结果
        """
        args = self.parse_args(delete_afrog_result_fields)
        id_list = args.pop('_id', [])
        for _id in id_list:
            query = {'_id': ObjectId(_id)}
            utils.conn_db('afrog_result').delete_one(query)

        return utils.build_ret(ErrorMsg.Success, {'_id': id_list})

