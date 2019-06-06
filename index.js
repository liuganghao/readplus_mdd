const aliOss = require('ali-oss');
const mongoose = require('mongoose');
const fs = require('fs-extra');
//const vm = require('vm');
const crypto = require('crypto');
const jwk2pem = require('pem-jwk').jwk2pem
const jwt = require('jsonwebtoken')
const request = require('request');

const utils = {
    config: {
        // model: {
        //     type: 'oss',
        //     config: {
        //         region: 'oss-cn-beijing',
        //         accessKeyId: 'LTAIE4YkQcigzTlt',
        //         accessKeySecret: 'RKjIyjF8uWi1HmCRr7BcGbEkxNJW6c',
        //         bucket: 'esread-dev'
        //     },
        // },
        // model: { type: 'local', config: '.' },
        model: { type: 'github', config: 'liuganghao/readplus_model' },
        env: 'dev',
        mongoUri: 'mongodb://root:123456789a@ds117816.mlab.com:17816/demo',
        jwt: {
            privateKey: { "kty": "RSA", "kid": "67174182967979709913950471789226181721", "alg": "ES256", "n": "oH5WunqaqIopfOFBz9RfBVVIIcmk0WDJagAcROKFiLJScQ8N\_nrexgbCMlu-dSCUWq7XMnp1ZSqw-XBS2-XEy4W4l2Q7rx3qDWY0cP8pY83hqxTZ6-8GErJm\_0yOzR4WO4plIVVWt96-mxn3ZgK8kmaeotkS0zS0pYMb4EEOxFFnGFqjCThuO2pimF0imxiEWw5WCdREz1v8RW72WdEfLpTLJEOpP1FsFyG3OIDbTYOqowD1YQEf5Nk2TqN\_7pYrGRKsK3BPpw4s9aXHbGrpwsCRwYbKYbmeJst8MQ4AgcorE3NPmp-E6RxA5jLQ4axXrwC0T458LIVhypWhDqejUw", "e": "AQAB", "d": "aQsHnLnOK-1xxghw2KP5JTZyJZsiwt-ENFqqJfPUzmlYSCNAV4T39chKpkch2utd7hRtSN6Zo4NTnY8EzGQQb9yvunaiEbWUkPyJ6kM3RdlkkGLvVtp0sRwPCZ2EAYBlsMad9jkyrtmdC0rtf9jerzt3LMLC7XWbnpC3WAl8rsRDR1CGs\_-u4sfZfttsaUbJDD9hD0q4NfLDCVOZoQ\_8wkZxyWDAQGCe6GcCbu6N81fTp2CSVbiBj7DST\_4x2NYUA2KG8vyZYcwviNTxQzk4iPfdN2YQz\_9aMTZmmhVUGlmTvAjE5ebBqcqKAS0NfhOQHg2uR46eBKBy\_OyVOLohsQ", "p": "8Tdo3DCs-0t9JMtM0lYqPRP4wYJs37Rv6S-ygRui2MI\_hadTY9I2A199JMYw7Fjke\_wa3gqJLa98pbybdLWkrOxXbKEkwE4uc4-fuNjLbUTC5tqdM5-nXmpL887uREVYnk8FUzvWeXYTCNCb7OLw5l8yPJ1tR8aNcd0fJNDKh98", "q": "qlRrGSTsZzBkDgDi1xlCoYvoM76cbmxrCUK-mc\_kBRHfMjlHosxFUnAbxqIBE4eAJEKVfIJLQrHFvIDjQb3kM9ylmwMCu9f8u9DHrT8J7LSDlLqDaXuiM2oiKtW3bAaBPuiR7sVMFcuB5baCebHU487YymJCBTfeCZtFdi6c4w0", "dp": "gVCROKonsjiQCG-s6X4j-saAL016jJsw-7QEYE6uiMHqR\_6iJ\_uD1V8Vuec-RxaItyc6SBsh24oeqsNoG7Ndaw7w912UVDwVjwJKQFCJDjU0v4oniItosKcPvM8M0TDUB1qZojuMCWWRYsJjNSWcvAQA7JoBAd-h6I8AqT39tcU", "dq": "BckMQjRg2zhnjZo2Gjw\_aSFJZ8iHo7CHCi98LdlD03BB9oC\_kCYEDMLGDr8d7j3h-llQnoQGbmN\_ZeGy1l7Oy3wpG9TEWQEDEpYK0jWb7rBK79hN8l1CqyBlvLK5oi-uYCaiHkwRQ4RACz9huyRxKLOz5VvlBixZnFXrzBHVPlk", "qi": "M5NCVjSegf\_KP8kQLAudXUZi\_6X8T-owtsG\_gB9xYVGnCsbHW8gccRocOY1Xa0KMotTWJl1AskCu-TZhOJmrdeGpvkdulwmbIcnjA\_Fgflp4lAj4TCWmtRI6982hnC3XP2e-nf\_z2XsPNiuOactY7W042D\_cajyyX\_tBEJaGOXM" },
            publicKey: { "kty": "RSA", "kid": "67174182967979709913950471789226181721", "alg": "ES256", "n": "oH5WunqaqIopfOFBz9RfBVVIIcmk0WDJagAcROKFiLJScQ8N\_nrexgbCMlu-dSCUWq7XMnp1ZSqw-XBS2-XEy4W4l2Q7rx3qDWY0cP8pY83hqxTZ6-8GErJm\_0yOzR4WO4plIVVWt96-mxn3ZgK8kmaeotkS0zS0pYMb4EEOxFFnGFqjCThuO2pimF0imxiEWw5WCdREz1v8RW72WdEfLpTLJEOpP1FsFyG3OIDbTYOqowD1YQEf5Nk2TqN\_7pYrGRKsK3BPpw4s9aXHbGrpwsCRwYbKYbmeJst8MQ4AgcorE3NPmp-E6RxA5jLQ4axXrwC0T458LIVhypWhDqejUw", "e": "AQAB" }
        },
        oss: {
            db: {
                rolearn: "acs:ram::1484545477798971:role/oss-esread-db",
                region: 'oss-cn-beijing',
                accessKeyId: 'LTAIV6xZrhKO4onQ',
                accessKeySecret: 'xUy1SQKj63uPzZL2CL9unIjDfHYVBw',
                bucket: 'esread-db',
                expiration: 15 * 60,
                policy: {
                    Statement: [
                        {
                            Effect: "Allow",
                            Action: [
                                "oss:GetObject",
                                "oss:AbortMultipartUpload",
                                "oss:PutObject",
                                "oss:PostObject"
                            ],
                            Resource: [
                                "acs:oss:*:*:esread-db",
                                "acs:oss:*:*:esread-db/*"
                            ]
                        }
                    ],
                    Version: "1"
                }
            }
        }
    },
    fslist: [],
    initMongodb: async () => {
        await mongoose.connect(config.mongoUri, { useNewUrlParser: true });
    },
    getJSON: async (ctx) => {
        let generateDBSchema = (model) => {
            let _getSimpleType = (type) => {
                let rt
                switch (type) {
                    case 'int':
                    case 'integer':
                        rt = {
                            type: mongoose.Schema.Types.Number,
                            get: v => Math.round(v),
                            set: v => Math.round(v),
                        }
                        break
                    case 'double':
                        rt = { type: mongoose.Schema.Types.Number }
                        break;
                    case 'decimal':
                        rt = { type: mongoose.Schema.Types.Decimal128 }
                        break;
                    case 'date':
                        rt = {
                            type: mongoose.Schema.Types.Date,
                            set: v => new Date(v.getUTCFullYear(), v.getUTCMonth(), v.getUTCDate()),
                        }
                        break
                    case 'datetime':
                        rt = { type: mongoose.Schema.Types.Date }
                        break;
                    case 'boolean':
                    case 'bool':
                        rt = { type: mongoose.Schema.Types.Boolean }
                        break;
                    case 'imageobject':
                    case 'fileobject':
                    case 'html':
                        rt = { type: mongoose.Schema.Types.Buffer }
                        break;
                    case 'image':
                    case 'file':
                    case 'string':
                        rt = { type: mongoose.Schema.Types.String }
                        break;
                }
                return rt
            }
            let _getSchema = (e, model) => {
                let schema = {};
                if (e) {
                    for (const p of e.propertylist) {
                        if (p && p.code && p.type
                            && p.code != 'id'
                            && p.code != '_id'
                            && p.code != '__v') {
                            let type = p.type.toLowerCase()
                            schema[p.code] = _getSimpleType(type)
                            if (!schema[p.code]) {
                                if (type.startsWith('enum_')) {
                                    schema[p.code] = { type: mongoose.Schema.Types.String }
                                } else if (type.startsWith('ref_')) {
                                    schema[p.code] = mongoose.Schema.Types.ObjectId
                                } else if (type.startsWith('list')) {
                                    if (type.indexOf('<') < 0 || type.indexOf('>') < 0)
                                        throw new Error('model:' + model.tablename + ' propertytype:' + p.code + ' type error:' + p.type)
                                    let subtype = p.type.split('<')[1].split('>')[0].trim()
                                    if (model.sublist && model.sublist.length > 0) {
                                        let subentity = model.sublist.find(f => f.code.toLowerCase() == subtype.toLowerCase())
                                        if (subentity) {
                                            schema[p.code] = [_getSchema(subentity, model)]
                                        } else {
                                            schema[p.code] = [_getSimpleType(subtype.toLowerCase())]
                                        }
                                    } else {
                                        schema[p.code] = [_getSimpleType(subtype.toLowerCase())]
                                    }
                                }
                            }
                            if (p.option && p.option.length > 0) {
                                for (const op of p.option) {
                                    try {
                                        schema[p.code][op.key] = eval(op.val)
                                    } catch (error) {
                                        console.error(error)
                                        throw Object.assign({
                                            'entity': model.tablename,
                                            'property': p.code,
                                            'property_option': op.val
                                        }, error)
                                    }
                                }
                            }
                        }
                        else schema[p.code] = { any: mongoose.SchemaTypes.Mixed };
                    }

                } else {
                    schema = { any: mongoose.SchemaTypes.Mixed };
                }
                return schema
            }

            let schema = _getSchema(model.entity, model)

            if (model.entity.statemachine && model.entity.statemachine.length > 0) {
                for (const action of model.entity.statemachine) {
                    schema[action.code + 'at'] = mongoose.Schema.Types.Date
                    schema[action.code + 'by'] = mongoose.Schema.Types.ObjectId
                    schema[action.code + 'by_name'] = mongoose.Schema.Types.String
                }
            }
            return schema;
        }
        let generateJSON = async (entityfullname) => {
            let replaceall = function replaceall(str, from, to) {
                if (str && from != to)
                    while (str.indexOf(from) >= 0) { str = str.replace(from, to); }
                return str;
            }
            let istable = function istable(str) {
                let temp = replaceall(str, '-', '')
                temp = replaceall(temp, '|', '')
                if (temp.trim()) return false
                return true
            }
            let isstate = function isstate(str) {
                if (str.indexOf('digraph G') >= 0) return true
                else return false
            }
            let isExistOss = async (osspath, ossClient) => {
                try {
                    await ossClient.head(osspath)
                    return true
                } catch (error) {
                    return false
                }
            }
            let getGithubReadplus_model = (mfile, gitrep) => {
                return new Promise((resolve, reject) => {
                    let options = {
                        method: 'GET',
                        url: `https://raw.githubusercontent.com/${gitrep}/master/${mfile}`,
                        headers:
                        {
                            //'cache-control': 'no-cache',
                            Connection: 'keep-alive',
                            //'accept-encoding': 'gzip, deflate',
                            Host: 'raw.githubusercontent.com',
                            //'Cache-Control': 'no-cache',
                            Accept: '*/*',
                            //'User-Agent': 'PostmanRuntime/7.13.0',
                        }
                    };

                    request(options, async function (error, response, body) {
                        if (error) reject(error)
                        else if (response.statusCode != 200)
                            reject(response.statusMessage + ":" + body)
                        else {
                            try {
                                let rt = body
                                //console.log(rt)
                                resolve(rt)
                            } catch (error) {
                                console.error(body)
                                reject(error)
                            }
                        }

                    });
                    //reject('error')
                })

            }
            let getMDFile = async (entityfullname) => {
                let mfile = replaceall(entityfullname, '.', '/') + '.entity.md';
                let filecontent, mstr
                switch (utils.config.model.type.toLowerCase().trim()) {
                    case 'oss':
                        let ossClient = new aliOss.STS({
                            region: utils.config.model.config.region,
                            accessKeyId: utils.config.model.config.accessKeyId,
                            accessKeySecret: utils.config.model.config.accessKeySecret,
                            bucket: utils.config.model.config.bucket
                        });
                        if (isExistOss(mfile, ossClient)) {
                            filecontent = await ossClient.get(mfile)
                            mstr = filecontent.content.toString();
                        }
                        break;
                    case 'local':
                        filecontent = fs.readFileSync(mfile);
                        mstr = filecontent.toString();
                        break;
                    case 'github':
                    default:
                        mstr = filecontent = await getGithubReadplus_model(mfile, utils.config.model.config)
                        break;
                }
                mstr = replaceall(mstr, '\r\n', '\n')
                //let service = entityfullname.split('.')[0]
                let com = entityfullname.split('.')[0]
                let entitycode = entityfullname.split('.')[1]
                return { com, entitycode, mstr };
            }
            let { com, entitycode, mstr } = await getMDFile(entityfullname);
            let obj = {
                createdat: new Date().toLocaleString(),
                com: com,
                tablename: com + '_' + entitycode
            }
            let nl = '\n'                                                                      //(process.platform === 'win32' ? '\r\n' : '\n')

            for (let index = 1; index < mstr.split('$$').length; index++) {
                const seg = mstr.split('$$')[index];
                let lines = seg.split(nl)
                if (!lines[0]) continue;
                let entity = {}
                if (lines[0].trim() == 'entity') {
                    obj.entity = entity
                } else {
                    if (!obj[lines[0].trim() + 'list']) obj[lines[0].trim() + 'list'] = []
                    obj[lines[0].trim() + 'list'].push(entity)
                }
                let proplist = seg.split(']:')
                for (let index = 0; index < proplist.length; index++) {
                    let p = proplist[index]
                    if (proplist.length == index + 1) continue
                    let np = proplist[index + 1]
                    let tlines = np.split(nl)
                    let leftkey = p.split(nl).slice(-1)[0]
                    if (!tlines[0]) {
                        if (istable(tlines[2])) {
                            entity[leftkey] = []
                            if (tlines.length <= 3) continue
                            for (let index = 3; index < tlines.length; index++) {
                                let tl = tlines[index];
                                if (!tl) break
                                let clist = tl.split('|')
                                let proplistitem = {}
                                for (let index = 0; index < clist.length; index++) {
                                    let c = clist[index].trim();
                                    if (c) {
                                        if (tlines[1].split('|').length <= index)
                                            console.error(`错误：${mfile},表头：${JSON.stringify(tlines[1])},当前索引：${index}，请检查${JSON.stringify(clist)}的|数量`)
                                        let header = tlines[1].split('|')[index].trim()
                                        if (c.split(':').length > 1) {
                                            proplistitem[header] = []
                                            for (const item of c.split('&')) {
                                                let opitem = item.split(':')
                                                proplistitem[header].push({
                                                    key: opitem[0].trim(),
                                                    val: opitem[1].trim()
                                                })
                                            }
                                        } else
                                            proplistitem[header] = c
                                    }
                                }
                                entity[leftkey].push(proplistitem)
                            }
                        } else if (isstate(tlines[2])) {
                            entity[leftkey] = []
                            for (let index = 3; index < tlines.length - 1; index++) {
                                const opline = tlines[index];
                                if (opline.trim() == "{" || opline.trim() == '}') continue
                                if (opline.trim() == '\`\`\`' || opline.trim() == '') break
                                let tempitem = {
                                    // pmlist: [{ code: 'id', name: 'ID', type: 'String', index: 990, required: true },
                                    // { code: 'changeset', name: '更新集合', type: 'Array', index: 995, required: false }]
                                }
                                tempitem.code = opline.split('[label="')[1].split(' ')[0]
                                tempitem.name = opline.split('[label="')[1].split(' ')[1].split('"')[0]
                                tempitem.index = index * 10 + 100

                                tempitem.fromstate = {
                                    code: opline.split('->')[0].split('"')[1].split(' ')[0],
                                    name: opline.split('->')[0].split(' ')[1].split('"')[0]
                                }
                                tempitem.tostate = {
                                    code: opline.split('->')[1].split('"')[1].split(' ')[0],
                                    name: opline.split('->')[1].split(' ')[1].split('"')[0]
                                }
                                entity[leftkey].push(tempitem)
                            }
                        }
                    } else
                        entity[leftkey] = tlines[0].trim()
                }
            }
            // let fname = mfile.replace('.md', '.g.json')
            // if (path.basename(mfile) == '.entity.md')
            //     fname = fname.replace('.entity.g.json', path.dirname(mfile).split(path.sep).slice(-1)[0] + '.entity.g.json')
            // fs.writeJSONSync(fname, obj, { spaces: 4 })
            // if (obj && obj.entity && obj.entity.statemachine && obj.entity.statemachine.length > 0)
            //     obj.firstAction = obj.entity.statemachine.sort((a, b) => a.index - b.index)[0].fromstate.code
            return obj
        }
        let fslist = utils.fslist
        let entityfullname = ctx.entity
        if (fslist.findIndex(f => f.entityfullname == entityfullname) < 0) {
            let obj = {
                model: await generateJSON(entityfullname),
                entityfullname: entityfullname
            }
            obj.mongoSchema = generateDBSchema(obj.model)
            if (!mongoose.models[obj.model.tablename])
                mongoose.model(obj.model.tablename, new mongoose.Schema(obj.mongoSchema, { timestamps: { createdAt: 'createdat', updatedAt: 'updatedat' } }), obj.model.tablename)
            //obj.mongoModel = mongoose.models[obj.model.tablename]
            fslist.push(obj)
        }
        return fslist.find(f => f.entityfullname == entityfullname).model
    },

    getMongoModel: async (ctx) => {
        let model = await utils.getJSON(ctx)
        return mongoose.models[model.tablename]
    },
    decrypt: function (str, secret) {
        var decipher = crypto.createDecipher('aes192', secret);
        var dec = decipher.update(str, 'hex', 'utf8');
        dec += decipher.final('utf8');
        return dec;
    },
    _afterRun: (callback, rt) => {
        callback(null, {
            isBase64Encoded: false,
            statusCode: 200,
            body: {
                _debug_ctx: ctx,
                data: rt,
            }
        });
    },
    _beforeRun: (body = {}) => {
        //let eventobj = JSON.parse(event.toString());
        //let body = JSON.parse(eventobj.body || "{}");

        let ctx = {};
        ctx.IdToken = body.IdToken; //|| "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjY3MTc0MTgyOTY3OTc5NzA5OTEzOTUwNDcxNzg5MjI2MTgxNzIxIn0.eyJpZCI6IjMxMzIzMzM0MzUzNjM3MzgzOTMwMzEzMiIsIm5hbWUiOiJyZWFjdCIsInBob25lIjoiYTZhYmIzNTUzOWY0YTNjYjQwMTlkZjljNDM1YzRjMDEiLCJwbGF0Zm9ybSI6ImY1YTUxYmIzMDEzY2VhMWU2YWNiOWMwN2E1OTQ1ZDQ5IiwianRpIjoiZXVtaXkxSEs5RzdTN2hCRCIsImV4cCI6MTU1NTg0NTM0MCwiaWF0IjoxNTU1MjQwNTQwfQ.GAWtZ2nsQgxJ4hzMADwc4FPO9JNb_CPf_4y61qZd4DtCE6fP5lLg6nLqIp8tRi-bq7XXVTdr6Rqg4Ucpq4LHXt4jCZdYmtTi5WZ3vpPoX5un-fApUxOmLvfsExeC7ZkGa_yahcFjqBGTiNA8jlwLVDqPCW-rVregEIS3FDItE0PGiNXJMceiQD3TiIafkz6zHwgD_0vPw4wNeyT3JxgWBrNDC6MJ1WWeeUMqe8JXAN4jdslPKyXC5_i-4Lv2mD7xAHkCZurQVi_pF-vxCjy908lIS5RkNA8QYzRj9WNM9RkL7gyllHK8xCvS56VfaS9_5GRrfrsREHiq8lf_FP8_vQ"
        ctx.param = JSON.parse(body.param || "{}");
        ctx.entity = body.entity;
        ctx.method = body.method;
        let token = jwt.verify(ctx.IdToken, jwk2pem(utils.config.jwt.publicKey));
        ctx.userinfo = {
            _id: mongoose.Types.ObjectId(token.id),
            name: token.name,
            phone: utils.decrypt(token.phone, token.id + 'es.read'),
            role: utils.decrypt(token.role, token.id + 'es.read'),
        };
        return ctx;
    },
    _hookAfterCreate: async (entity, ctx) => {

    },
    _hookBeforeCreate: async (entity, ctx) => {
        let jsonModel = await utils.getJSON(ctx)
        // if (!entity.createdat)
        //     entity.createdat = new Date()
        if (!entity.createdby)
            entity.createdby = mongoose.Types.ObjectId(ctx.userinfo._id)
        if (!entity.createdby_name)
            entity.createdby_name = ctx.userinfo.name
        if (!entity.state && jsonModel && jsonModel.entity && jsonModel.entity.statemachine && jsonModel.entity.statemachine.length > 0)
            entity.state = jsonModel.entity.statemachine.sort((a, b) => a.index - b.index)[0].fromstate.code
    },
    _hookBeforeUpdate: async (entity, ctx) => {
        // if (!entity.updatedat)
        //     entity.updatedat = new Date()
        if (!entity.updatedby)
            entity.updatedby = mongoose.Types.ObjectId(ctx.userinfo._id)
        if (!entity.updatedby_name)
            entity.updatedby_name = ctx.userinfo.name
    },
    _hookBeforeRemove: async (entity, ctx) => {
        if (!ctx.param._id) throw Error('ctx.param._id不能为空')
    },
    _hookAfterRemove: async (ctx) => {

    },
    _hookBeforeChangeState: (entity, ctx) => {
        if (!ctx.param._id) throw Error('ctx.param._id不能为空')
        if (!ctx.param.action) throw Error('ctx.param.action不能为空')
    },
    _hookAfterChangeState: (entity, result, ctx) => {

    },
}
const crud =
{
    update: async (ctx) => {
        let changeset = ctx.param.changeset
        let Schema = await utils.getMongoModel(ctx)
        if (ctx.param._id) {
            if (changeset['state']) throw new Error('状态更新请调用对应的状态机方法，不支持在update时更新状态')
            if (changeset['createdby']) throw new Error('不支持在更新时修改创建人')
            if (changeset['createdat']) throw new Error('不支持在更新时修改创建时间')
            // let entity = new Schema(ctx.param._id);
            //todo changeset['__v']
            await utils._hookBeforeUpdate(changeset, ctx);
            let result = await Schema.updateOne({ _id: ctx.param._id }, { $set: changeset, $inc: { __v: 1 } })
            //await utils._hookAfterUpdate(entity, ctx);
            return result;
            // await utils.activityLog.edit(ctx, changeset._id, model);
        } else if (ctx.param.where) {
            if (changeset['state']) throw new Error('状态更新请调用对应的状态机方法，不支持在update时更新状态')
            if (changeset['createdby']) throw new Error('不支持在更新时修改创建人')
            if (changeset['createdat']) throw new Error('不支持在更新时修改创建时间')
            // let entity = new Schema(ctx.param._id);
            //todo changeset['__v']
            await utils._hookBeforeUpdate(changeset, ctx);
            let result = await Schema.updateOne(ctx.param.where, { $set: changeset, $inc: { __v: 1 } }, { upsert: true })
            //await utils._hookAfterUpdate(entity, ctx);
            return result;
            // await utils.activityLog.edit(ctx, changeset._id, model);
        } else {
            let entity = new Schema(changeset);
            await utils._hookBeforeCreate(entity, ctx);
            let savedEntity = await entity.save();
            await utils._hookAfterCreate(savedEntity, ctx);
            return savedEntity;
            // await utils.activityLog.add(ctx, result._id, model);
        }
    },
    remove: async (ctx) => {
        let Schema = await utils.getMongoModel(ctx)
        let jsonModel = await utils.getJSON(ctx)
        let result
        let entity = await Schema.findById(ctx.param._id);
        let firstAction = jsonModel.entity.statemachine.sort((a, b) => a.index - b.index)[0]
        if (jsonModel.entity.statemachine && jsonModel.entity.statemachine.length > 0 && entity.state == firstAction.fromstate.code && !entity[firstAction.code + 'at']) {
            //草稿且只存在草稿状态可删
            utils._hookBeforeRemove(entity, ctx)
            result = await entity.remove()
        }
        //await utils.activityLog.remove(ctx, changeset._id, current._schema);
        utils._hookAfterRemove(ctx)
        return result
    },
    first: async (ctx) => {
        let Schema = await utils.getMongoModel(ctx)
        let result
        if (ctx.param._id)
            result = await Schema.findById(ctx.param._id).lean();
        else {
            list = await Schema.find(ctx.param.where || {}).lean().skip(ctx.param.skip || 0).limit(1).sort(ctx.param.sort || {});
            if (list.length > 0) result = list[0]
        }
        return result
    },
    table: async (ctx) => {
        let Schema = await utils.getMongoModel(ctx)
        let select = ctx.param.select || {}
        let where = ctx.param.where || {};
        let skip = ctx.param.skip || 0;
        let limit = ctx.param.limit || 10;
        let sort = ctx.param.sort || {};
        let result = await Schema.find(where).lean().select(select).skip(skip).limit(limit).sort(sort);
        let count = await Schema.countDocuments(where);
        return { list: result, total: count }
    },
    list: async (ctx) => {
        let Schema = await utils.getMongoModel(ctx)
        let select = ctx.param.select || {}
        let where = ctx.param.where || {};
        let skip = ctx.param.skip || 0;
        let limit = ctx.param.limit || 10;
        let sort = ctx.param.sort || {};
        let result = await Schema.find(where).lean().select(select).skip(skip).limit(limit).sort(sort);
        return result
    },
    count: async (ctx) => {
        let Schema = await utils.getMongoModel(ctx)
        let where = ctx.param.where || {};
        let result = await Schema.countDocuments(where)
        return result
    },
    changestate: async (ctx) => {
        let Schema = await utils.getMongoModel(ctx)
        let jsonModel = await utils.getJSON(ctx)

        let changeset = ctx.param.changeset || {};
        delete changeset.state
        let _id = ctx.param._id
        let action = ctx.param.action


        let entity = await Schema.findById(_id).lean();
        await utils._hookBeforeChangeState(entity, ctx);
        if (!(entity && entity._id)) throw new Error('没有找到记录')
        if (!jsonModel.entity.statemachine) throw new Error('没有状态机')

        let currState = jsonModel.entity.statemachine.find(s => (s.fromstate.code == entity.state || !entity.state) && s.code == action)
        if (!currState) {
            throw new Error(`操作${action}不正确，无法从状态${entity.state}触发`);
        }
        let actionat = action + 'at'
        let actionby = action + 'by'
        let actionbyname = action + 'by_name'
        changeset.state = currState.tostate.code
        changeset[actionat] = new Date()
        changeset[actionby] = ctx.userinfo._id
        changeset[actionbyname] = ctx.userinfo.name

        let result = await Schema.updateOne({ _id: _id }, {
            $set: changeset,
            $inc: { __v: 1 }
        });
        await utils._hookAfterChangeState(entity, result, ctx);
        //await utils.activityLog.changestate(ctx, _id, current._schema);
        return result
    },
    sts: async (ctx) => {
        let stsClient = new aliOss.STS({
            accessKeyId: utils.config.oss.db.accessKeyId,
            accessKeySecret: utils.config.oss.db.accessKeySecret,
        });
        let token = await stsClient.assumeRole(
            utils.config.oss.db.rolearn,
            utils.config.oss.db.policy,
            utils.config.oss.db.expiration,
            utils.config.oss.db.bucket
        );
        return {
            region: utils.config.oss.db.region,
            bucket: utils.config.oss.db.bucket,
            accessKeyId: token.credentials.AccessKeyId,
            accessKeySecret: token.credentials.AccessKeySecret,
            stsToken: token.credentials.SecurityToken,
        }
    },
};

module.exports = { utils, crud }
