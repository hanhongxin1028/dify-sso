import logging
from app.extensions.ext_database import db
from app.libs.helper import naive_utc_now
from app.models.account import Account, AccountStatus, TenantAccountJoin, TenantAccountRole, Tenant

logger = logging.getLogger(__name__)

class CustomSSOService:
    @staticmethod
    def get_or_create_account(username: str, nickname: str, client_ip: str) -> Account:
        """
        根据用户名（工号）查找或创建 Dify 账户
        """
        # 构造 Dify 账号所需的 Email
        user_email = f"{username}@jscn.oa"
        user_name = nickname if nickname else username
        
        # 默认角色
        user_role = TenantAccountRole.OWNER 

        try:
            # 1. 查找系统用户
            account = Account.get_by_email(user_email)

            # 2. 如果系统用户不存在，则创建系统用户
            if not account:
                logger.info("CustomSSO 创建新用户: %s", user_email)

                account = Account.create(
                    email=user_email,
                    name=user_name,
                    avatar=""
                )

                # 创建新工作空间（tenant）
                tenant = Tenant.create(name=f"{user_name}的工作空间")
                
                # 关联用户和工作空间
                TenantAccountJoin.create(tenant.id, account.id, user_role)

                # 设置当前空间
                account.current_tenant_id = tenant.id
            else:
                # 3. 如果用户已存在，检查是否有工作空间 (防止孤儿账号)
                existing_account_join = TenantAccountJoin.get_first_by_account_id(account.id)

                if not existing_account_join:
                    logger.info("CustomSSO 老用户 %s 无关联空间，正在补建...", user_email)
                    tenant = Tenant.create(name=f"{user_name}的工作空间")
                    TenantAccountJoin.create(tenant.id, account.id, user_role)
                    account.current_tenant_id = tenant.id
                else:
                    # 如果当前没有选中的租户，强制选一个
                    if not account.current_tenant_id:
                        account.current_tenant_id = existing_account_join.tenant_id

            # 4. 更新用户登录信息 (最后登录时间、IP、状态、昵称同步)
            account.last_login_at = naive_utc_now()
            account.last_login_ip = client_ip
            
            if account.status != AccountStatus.ACTIVE:
                account.status = AccountStatus.ACTIVE
            
            # 同步昵称：如果 SSO 传过来的昵称变了，更新本地数据库
            if account.name != user_name:
                logger.info("CustomSSO 更新用户昵称: %s -> %s", account.name, user_name)
                account.name = user_name

            db.session.add(account)
            db.session.commit()
            
            logger.info("CustomSSO 用户验证成功: %s", user_email)
            return account

        except Exception as e:
            logger.exception("CustomSSO 处理用户信息验证时发生错误: %s", str(e))
            db.session.rollback()
            raise e