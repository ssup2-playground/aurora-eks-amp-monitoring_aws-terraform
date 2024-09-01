## Provider
provider "aws" {
  region = local.region
}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }
}

provider "helm" {
  # to avoid issue : https://github.com/hashicorp/terraform-provider-helm/issues/630#issuecomment-996682323
  repository_config_path = "${path.module}/.helm/repositories.yaml" 
  repository_cache       = "${path.module}/.helm"

  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
    }
  }
}

provider "kubectl" {
  apply_retry_count      = 5
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  load_config_file       = false

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }
}

## Data
data "aws_availability_zones" "available" {}

## Locals
locals {
  name = "eks-db-monitoring"

  region   = "ap-northeast-2"
  azs      = slice(data.aws_availability_zones.available.names, 0, 3)
  vpc_cidr = "10.0.0.0/16"

  aurora_mysql_user           = "admin"
  aurora_mysql_password       = "adminadmin"
  aurora_postgresql_user      = "root"
  aurora_postgresql_password  = "rootroot"
}

## AMP
module "prometheus" {
  source = "terraform-aws-modules/managed-service-prometheus/aws"

  workspace_alias = format("%s-amp", local.name)
}

## VPC
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"

  name = format("%s-vpc", local.name)

  cidr             = local.vpc_cidr
  azs              = local.azs
  public_subnets   = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 4, k)]
  private_subnets  = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 4, k + 4)]
  database_subnets = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 4, k + 10)]

  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true
  enable_dns_support   = true

  manage_default_network_acl    = true
  manage_default_route_table    = true
  manage_default_security_group = true

  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1 # for AWS Load Balancer Controller
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1 # for AWS Load Balancer Controller
  }
}

## Aurora
module "aurora_mysql" {
  source = "terraform-aws-modules/rds-aurora/aws"

  name = format("%s-aurora-mysql", local.name)

  engine              = "aurora-mysql"
  skip_final_snapshot = true

  instance_class = "db.r5.large"
  instances = {
    one = {}
    two = {}
  }

  vpc_id                 = module.vpc.vpc_id
  create_db_subnet_group = false
  db_subnet_group_name   = module.vpc.database_subnet_group_name

  create_security_group = true
  security_group_rules = {
    ingress = {
      cidr_blocks = module.vpc.private_subnets_cidr_blocks
    }
  }

  manage_master_user_password = false
  master_username             = "admin"
  master_password             = "adminadmin"
}

module "aurora_postgresql" {
  source = "terraform-aws-modules/rds-aurora/aws"

  name = format("%s-aurora-postgresql", local.name)

  engine              = "aurora-postgresql"
  skip_final_snapshot = true

  instance_class = "db.r5.large"
  instances = {
    one = {}
    two = {}
  }

  vpc_id                 = module.vpc.vpc_id
  create_db_subnet_group = false
  db_subnet_group_name   = module.vpc.database_subnet_group_name

  create_security_group = true
  security_group_rules = {
    ingress = {
      cidr_blocks = module.vpc.private_subnets_cidr_blocks
    }
  }

  manage_master_user_password = false
  master_username             = "root"
  master_password             = "rootroot"
}

## EKS
module "eks" {
  source = "terraform-aws-modules/eks/aws"

  cluster_name = format("%s-eks", local.name)
  cluster_version = "1.28"

  vpc_id                          = module.vpc.vpc_id
  subnet_ids                      = module.vpc.private_subnets
  cluster_endpoint_public_access  = true

  enable_cluster_creator_admin_permissions = true
  
  ## Managed Nodegroups
  eks_managed_node_groups = {
    node = {
      min_size     = 3
      max_size     = 3
      desired_size = 3

      instance_types = ["m5.xlarge"]
      iam_role_additional_policies = {
        AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
      }
    }
  }

  ## Addons
  cluster_addons = {
    coredns = {
      addon_version = "v1.10.1-eksbuild.5"
    }
    vpc-cni = {
      addon_version = "v1.14.1-eksbuild.1"
    }
    kube-proxy = {
      addon_version = "v1.28.1-eksbuild.1"
    }
    aws-ebs-csi-driver = {
      addon_version = "v1.25.0-eksbuild.1"
      service_account_role_arn = module.irsa_ebs_csi_plugin.iam_role_arn
    }
  }

  ## Node Security Group
  node_security_group_additional_rules = {
    ingress_self_all = {
      description = "Node to node all ports/protocols"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "ingress"
      self        = true
    }

    ingress_grafana = {
      description              = "From grafana NLB"
      protocol                 = "-1"
      from_port                = 0
      to_port                  = 0
      type                     = "ingress"
      source_security_group_id = module.sg_grafana.security_group_id
    }
  }
}

module "irsa_ebs_csi_plugin" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name             = format("%s-irsa-ebs-csi-plugin", local.name)
  attach_ebs_csi_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa", "kube-system:ebs-csi-node-sa"]
    }
  }
}

## EKS / Load Balancer Controller
module "irsa_load_balancer_controller" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                              = format("%s-irsa-aws-load-balancer-controller", local.name)
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }
}

resource "helm_release" "aws_load_balancer_controller" {
  namespace  = "kube-system"
  name       = "aws-load-balancer-controller"
  chart      = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  version    = "v1.6.2"

  set {
    name  = "clusterName"
    value = module.eks.cluster_name
  }
  set {
    name  = "serviceAccount.name"
    value = "aws-load-balancer-controller"
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.irsa_load_balancer_controller.iam_role_arn
  }

  depends_on = [
    module.irsa_load_balancer_controller,
    helm_release.grafana,
  ]
}

## EKS / Grafana
module "sg_grafana" {
  source = "terraform-aws-modules/security-group/aws"

  name   = format("%s-grafana-sg", local.name)
  vpc_id = module.vpc.vpc_id

  ingress_with_cidr_blocks = [
    {
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = "127.0.0.1/32"
    }
  ]

  egress_with_cidr_blocks = [
    {
      from_port       = 0
      to_port         = 0
      protocol        = "-1"
      cidr_blocks     = "0.0.0.0/0"
    }
  ]
}

module "irsa_grafana" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                                       = format("%s-irsa-grafana", local.name)
  attach_amazon_managed_service_prometheus_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["observability:grafana"]
    }
  }
}

resource "helm_release" "grafana" {
  namespace        = "observability"
  create_namespace = true

  name       = "grafana"
  chart      = "grafana"
  repository = "https://grafana.github.io/helm-charts"
  version    = "v7.0.8"
 
  set {
    name  = "serviceAccount.name"
    value = "grafana"
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.irsa_grafana.iam_role_arn
  }

  values = [
    templatefile("${path.module}/helm-values/grafana.yaml", {
      region = local.region
      svc_sg = module.sg_grafana.security_group_id
      amp    = format("https://aps-workspaces.%s.amazonaws.com/workspaces/%s", local.region, module.prometheus.workspace_id)
    })
  ]
}

## EKS / ADOT Collector
module "irsa_adot_collector" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                                       = format("%s-irsa-adot-collector", local.name)
  attach_amazon_managed_service_prometheus_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["observability:adot-collector"]
    }
  }
}

data "kubectl_file_documents" "adot_collector" {
  content = templatefile("${path.module}/manifests/adot-collector.yaml",
    {
      region                    = local.region
      amp_role_arn              = module.irsa_adot_collector.iam_role_arn
      amp_remote_write_endpoint = format("https://aps-workspaces.%s.amazonaws.com/workspaces/%s/api/v1/remote_write", local.region, module.prometheus.workspace_id)
    }
  )
}

resource "kubectl_manifest" "adot_collector" {
  for_each = data.kubectl_file_documents.adot_collector.manifests
  yaml_body = each.value

  depends_on = [
    module.eks
  ]
}

## EKS / mysqld-exporter-one
resource "helm_release" "aurora-mysql-one" {
  namespace        = "observability"
  create_namespace = true

  name       = "aurora-mysql-one"
  chart      = "prometheus-mysql-exporter"
  repository = "https://prometheus-community.github.io/helm-charts"
  version    = "2.6.1"

  values = [
    templatefile("${path.module}/helm-values/mysqld-exporter-one.yaml", {
      endpoint = module.aurora_mysql.cluster_instances.one.endpoint
      user     = local.aurora_mysql_user 
      password = local.aurora_mysql_password
    })
  ]
}

## EKS / mysqld-exporter-two
resource "helm_release" "aurora-mysql-two" {
  namespace        = "observability"
  create_namespace = true

  name       = "aurora-mysql-two"
  chart      = "prometheus-mysql-exporter"
  repository = "https://prometheus-community.github.io/helm-charts"
  version    = "2.6.1"

  values = [
    templatefile("${path.module}/helm-values/mysqld-exporter-two.yaml", {
      endpoint = module.aurora_mysql.cluster_instances.two.endpoint
      user     = local.aurora_mysql_user 
      password = local.aurora_mysql_password
    })
  ]
}

## EKS / postgresql-exporter-one
resource "helm_release" "aurora-postgresql-one" {
  namespace        = "observability"
  create_namespace = true

  name       = "aurora-postgresql-one"
  chart      = "prometheus-postgres-exporter"
  repository = "https://prometheus-community.github.io/helm-charts"
  version    = "6.3.1"

  values = [
    templatefile("${path.module}/helm-values/postgresql-exporter-one.yaml", {
      endpoint = module.aurora_postgresql.cluster_instances.one.endpoint
      user     = local.aurora_postgresql_user 
      password = local.aurora_postgresql_password
    })
  ]
}

## EKS / postgresql-exporter-two
resource "helm_release" "aurora-postgresql-two" {
  namespace        = "observability"
  create_namespace = true

  name       = "aurora-postgresql-two"
  chart      = "prometheus-postgres-exporter"
  repository = "https://prometheus-community.github.io/helm-charts"
  version    = "6.3.1"

  values = [
    templatefile("${path.module}/helm-values/postgresql-exporter-two.yaml", {
      endpoint = module.aurora_postgresql.cluster_instances.two.endpoint
      user     = local.aurora_postgresql_user 
      password = local.aurora_postgresql_password
    })
  ]
}
