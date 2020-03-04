#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/netfilter_ipv4.h>
#include<linux/string.h>

#include<linux/mm_types.h>
#include<linux/gfp.h>
#include<linux/mm.h>
#include<linux/slab.h>
#include <linux/unistd.h>;
#include <linux/file.h>;
#include <linux/fs.h>;
#include <linux/sched.h>;
#include <asm/uaccess.h>;
#include <linux/tcp.h>;             
#include <asm/processor.h>;


MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("keng");
MODULE_DESCRIPTION("kernel module netfilter");
MODULE_VERSION("1.0");

//define and global 


typedef struct rule//定义防火墙规则链表
{
  char p;//黑名单白名单区别字符
  int mod;//过滤模式判别整型
  char str[16];//判别规则字符串
  struct rule *next;//指向下一规则
  //
  int pro;//规则过滤下规则与整型的对应
  int num[4];//要过滤的ip地址，分为四个整型
  int a,b;//内容过滤的字符位置域，
  char c,d;//字符值域
 
}LinkList;
LinkList *head;
int r_sign=0;//read_siugn

//function
static void read_file(void);/*read data from config，从文件读取配置规则*/
static void file_handle(void);//handle data，处理读取的数据

static int get_num(char a, char b, char c);//used by ip_to_char，转字符为数字
static void ip_to_char(LinkList *q);
/*ip of file translate to int 配置文件中的ip字符转为对应ip*/
static void pro_to_int(LinkList *q);
/*char pro to int pro(protocol)，同上，转对应的规则名字为整型*/
static void char_do(LinkList *q);//data handle，数据处理
static int get_10(int k);
static unsigned int handle_fun(struct sk_buff *skb);
/*根据规则处理skb包，返回丢弃或者接受的选项*/

/* NF_INET_POST_ROUTING 出去的数据包的hook函数*/
unsigned int post_routing_hook(unsigned int hooknum, 
                              struct sk_buff *skb,
                              const struct net_device *in,
                              const struct net_device *out,
                              int (*okfn)(struct sk_buff *))
 {
      if(r_sign==0)
         read_file();
       
      return handle_fun(skb);

     }
//hook函数结构体配置
struct nf_hook_ops post_routing_ops =
 {
     .hook = post_routing_hook,
     .pf = PF_INET,
     .hooknum = NF_INET_POST_ROUTING,
     .priority = NF_IP_PRI_FIRST
 };

  
 /* NF_INET_PRE_ROUTING 进入的hook函数*/
unsigned int pre_routing_hook(                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                
          unsigned int hooknum,
          struct sk_buff *skb,
          const struct net_device *in,
          const struct net_device *out,
          int (*okfn)(struct sk_buff *))
  {
      if(r_sign==0)
         read_file();
       
      return handle_fun(skb);
  }
  //hook函数结构体配置
  struct nf_hook_ops pre_routing_ops =
  {
      .hook = pre_routing_hook,
      .pf = PF_INET,
      .hooknum = NF_INET_PRE_ROUTING,
      .priority = NF_IP_PRI_FIRST
  };
//do_funtion
static void read_file(void)
{
  mm_segment_t fs;
  struct file *fp = NULL;//定义文件指针
  loff_t pos;
 
  fp = filp_open("/home/q528288/list/xp.config",O_RDWR,0644);//打开文件，读模式
  if (IS_ERR(fp)){
        printk("create file error/n");
    }
  

  char buf1[100];//定义存储的缓冲区
  char buf[100];
  int i=0;
  
  for(i=0;i<100;i++)//初始化缓冲区
     buf1[i]='\0';
  fs=get_fs();
  set_fs(KERNEL_DS);//设置操作环境为内核模式
  pos =0;
  vfs_read(fp,buf1, sizeof(buf), &pos);//读取buf长度的字符到buf1
  filp_close(fp,NULL);//关闭文件指针
  set_fs(fs);
  
 LinkList *p,*q;
  head = kmalloc(sizeof(*p),GFP_KERNEL);//分配链表头（头不存储规则）
  head->next=NULL; 
  
  p=head;

  int j=0;

 // printk("read : %s\n",buf1);struct rule
  //printk("test:----------\n");
/*
  i=0;
  while(buf1[i]!='\0')
 { 
   printk("i:%d asci:%d  buf1: %c \n",i,(int)buf1[i],buf1[i]);
   i++;
  }
  
*/
  i=0;
 while(buf1[i]!='\0')//遍历读取的字符串
   {
   if(buf1[i]=='*'||buf1[i]=='#')//检测黑白名单，出现代表是有效规则
        {
         q=kmalloc(sizeof(*p),GFP_KERNEL);//分配规则空间
         q->p=buf1[i];//黑白名单区别符号赋值
         i=i+2;//直接至后一个有效字符，跳过空格
         q->mod=(int)(buf1[i]-'0');//对模式取值
         if(buf1[i+1]!=' ')//判断是否是双位数字字符。是就更改模式值
           {
            q->mod=q->mod*10+(int)(buf1[i+1]-'0');
            i=i+3;
            }
         else i=i+2;
         j=0;
   /*下面是检测是否到该条规则尾或者下一条规则头，读取要求的字符串*/
         while(buf1[i]!='*'&&
               buf1[i]!='#'&&
               buf1[i]!='\0'&&
               (int)buf1[i]!=10&&
               j<15)
            {
             q->str[j]=buf1[i];
             j++;
             i++;
            }
           
           q->str[j]='\0';
           p->next=q;
           p=q;
          }  
    else if(buf1[i]=='\0')
              break;
    else
          i++;
     
    }
    
    p->next=NULL;//末尾配空指针
    p=head->next;
   
    //while(p!=NULL)
      //{

     //printk("p->p:%c\n",p->p);
     //printk("p->mod:%d\n",p->mod);
    // printk("p->str:%s\n",p->str);
     //p=p->next;
     //}
     file_handle();
}

static int get_num(char a, char b, char c)
{
/*传入三个字符。如1 2 5，转变为整型的125*/
	int x = (int)(a - '0');
	int y = (int)(b - '0');
	int z = (int)(c - '0');
	//printf("%d %d %d\n",x,y,z);//测试点
	return x * 100 + y * 10 + z;
}

static void file_handle(void)//读取内容处理
{
 LinkList *p;
 p=head;
 if(p->next!=NULL)
  {
   while(p->next!=NULL)
    {
      p=p->next;
      switch(p->mod)//根据规则内的过滤模式跳转不同的处理函数
       {
         case 1:
               ip_to_char(p);//ip处理
               break;
         case 2:
               pro_to_int(p);//规则处理
               break;
         case 3:
               char_do(p);//内容处理
               break;
         case 41:
               ip_to_char(p);
               break;
         case 42:
               pro_to_int(p);
               break;
         case 43:
               char_do(p);
               break;

        }

    }
  }
r_sign=1;
}

static void char_do(LinkList *q)
{
 int c=0;
 int n=0;
 int num1[5];
 int i=0;;
 int num2[5];
 int j=0;
 int t;
 int k=1;
 while(q->str[n]!='\0')
/*遍历字符串，根据数字-数字-字符字符的规则处理，两个数字根据-来叛变输出，字符直接进行复制*/
 {
    if(q->str[n]>='0'&&q->str[n]<='9'&&c<2)
       {
         if(c==0)
           {
            num1[i]=(int)(q->str[n]-'0');
            i++;
            n++;
           }
          else if(c==1)
            {
            num2[j]=(int)(q->str[n]-'0');
            j++;
            n++;
            }
       }
    else if(q->str[n]=='-'&&c<2)
    {
      c++;
      n++;
     }
    else
    {
     q->c=q->str[n];
     
     q->d=q->str[n+1];
     
     //printf("1:%c 2:%c %d %d\n",q->str[n],q->str[n+1],n++,n+1);
     break;
    }
 }
 q->a=0;
 q->b=0;
 for(t=i-1;t!=-1;t--)
  {
    q->a+=num1[t]*get_10(k);
    //printf("a:%d\n",q->a);
    k++;
  }
  k=1;
  for(t=j-1;t!=-1;t--)
  {
    q->b+=num2[t]*get_10(k);
    k++;
  }
 
}

static int get_10(int k)
{
/*取10的k次幂。此处没有用递归算法，直接循环*/
  int t=1;
  int i;
  if(k==1)
    return 1;
  for(i=1;i<k;i++)
    t=t*10;   
  return t;
}


static void pro_to_int(LinkList *q)
{
 switch(q->str[0])
/*从首个字符开始进行判断规则名字，赋值定义的值*/
 {
   case 'i':
           if(q->str[1]=='c')//icmp
               q->pro=1;
           else if(q->str[2]=='g')//igmp
               q->pro=2;
           else if(q->str[2]=='p')//ip
               q->pro=0;
           else//idp
               q->pro=22;
           break;
   case 't'://tcp
           q->pro=6;
           break;
   case 'u'://udp
           q->pro=17;
           break;
   case 'r'://raw
           q->pro=256;
           break;
   case 'm'://max
           q->pro=255;
           break;
   case 'n'://nd
           q->pro=77;
           break;
        
   case 'g'://ggp
           q->pro=3;
           break;
   case 'p'://pup
           q->pro=12;
           break;
 }

}


static void ip_to_char(LinkList *q)
{
  char *x;
  x = q->str;
  char a, b, c;
  int ct=0;
  int ct2 = 0;
  a = b = c = '0';
  while (*x != '\0')
/*根据点来进行分段处理ip的字符表示，用ct来表明是第几个点，遇点则对前面的值进行字符转整型处理*/
	{
	 if (*x != '.')
	   {
		if (ct == 0)
		{
			c = *x;
			ct++;
			x++;
		}
		else if (ct == 1)
		{
			b = c;
			c = *x;
			ct++;
			x++;
		}
		else if (ct == 2)
		{
			a = b;
			b = c;
			c = *x;
			ct = 0;
		}
			
	}
	else
	{
		q->num[ct2] = get_num(a, b, c);
		a = b = c = '0';
		ct = 0;
		ct2++;
		x++;
	}
	}
	q->num[ct2] = get_num(a, b, c);
	/*printf("%d.%d.%d.%d\n",q->num[0],q->num[1],q->num[2],q->num[3]);//测试点*/
	
}
/*
void test()
{
  LinkList *p;
  p=head;
  p=p->next;
  while(p!=NULL)
  {
   printf("%c %d %s\n",p->p,p->mod,p->str);
   if(p->mod==1)
    printf("%d.%d.%d.%d\n------------\n",p->num[0],p->num[1],p->num[2],p->num[3]);
   else if(p->mod==2)
     printf("%d\n---------\n",p->pro);
   else
     printf("%d %d %c %c\n",p->a,p->b,p->c,p->d);

   p=p->next;
  }

}
*/
static unsigned int handle_fun(struct sk_buff *skb)
//规则判别函数，判断数据包是否符合规则
{
  struct iphdr *ip_header;
  ip_header = ip_hdr(skb);
  static unsigned char *ip_src;
  static unsigned char *ip_dst;
  LinkList *p;
  p=head;
  int ip_s[4];
  int ip_d[4];
  int i;
  int tcpoff,tcplen,payload_len;
  unsigned char *x;
  x=skb->data;
  ip_src=(unsigned char *)&(ip_header->saddr);
//取地址，转为无符号整型，之后将使用数组方式访问
  ip_dst=(unsigned char *)&(ip_header->daddr);

  if(ip_header->protocol==6)/*tcp有效负载计算函数，这里赋值了tcp的有效负载和指向tcp有效负载的头指针*/
        {
         
         tcpoff=skb_network_offset(skb)+(ip_header->ihl<<2);/*求得非tcp数据包所占的长度*/
         tcplen=skb->len-tcpoff;//tcp数据包长度=skb的线性和非线性之和-非tcp部分
         payload_len=tcplen-tcp_hdr(skb)->doff*4;
//有效贼和=tcp输出包长度-tcp头部长度
         x = (unsigned char*)(skb->data+(tcp_hdr(skb)->doff+5)*4);/*指向数据包实际数据的指针加上固定的ip头长度，和可变的tcp头长度（ip为20字节）*/
        }
  else if(ip_header->protocol==17)//同上，此处为udp
         {
          x+=28;
          payload_len=skb->len-skb->data_len-28;
         }
 else
       {
        payload_len=0;/*skb->len-skb->data_len;为防止误伤，默认非tcp和udp的有效载荷为零，若要针对别的协议进行内容过滤，则要考虑别的协议的实际数据存储方式*/
        }
    
  int u_sign=0;
  int s_sign=0;
  for(i=0;i<=3;i++)
//遍历赋值ip地址的四个ip整型，在上面已经进行过处理
    {
      ip_s[i]=(int)ip_src[i];
      ip_d[i]=(int)ip_dst[i];
    }
        
  if(p->next!=NULL)
    p=p->next;

while(p!=NULL)
  {
   switch(p->mod)
    {
      case 1://判断四个整型是否相等
            if((ip_s[0]==p->num[0]&&
                ip_s[1]==p->num[1]&&
                ip_s[2]==p->num[2]&&
                ip_s[3]==p->num[3])
             ||(ip_d[0]==p->num[0]&&
                ip_d[1]==p->num[1]&&
                ip_d[2]==p->num[2]&&
                ip_d[3]==p->num[3]))
                {
                  if(p->p=='*')
                    { 
                       printk("open:%d.%d.%d.%d\n",p->num[0],p->num[1],p->num[2],p->num[3]); 
                       return NF_ACCEPT;//这里代表放过
                     }
                  else
                      {
                        printk("kill:%d.%d.%d.%d\n",p->num[0],p->num[1],p->num[2],p->num[3]);               
                        return NF_DROP;//代表丢弃
                          }
                  }
             break;
      case 2:
             if(ip_header->protocol==p->pro)//判断规则对应的整型是否相等
               {
                 if(p->p=='*')
                      {
                       printk("open:%d\n",p->pro);
                       return NF_ACCEPT;
                      }
                   else
                      {
                       printk("kill:%d\n",p->pro);
                        return NF_DROP;
                      }
               }
             break;
      case 3:   
            if(p->a>payload_len||payload_len==0)//对于有效载荷为零的不处理
                break;
     
            for(i=1;i<p->a;i++)//遍历至a对应的位置
                   x++;
            for(i=p->a;i<=p->b&&i<=payload_len;i++)//从a开始至b进行遍历甄别
                 { 
                   if((int)*x>=(int)p->c&&(int)*x<=(int)p->d)
                         x++;
                   else
                         break;
                    }
            if(i>p->b||i>payload_len)
               { 
                if(p->p=='*')
                   return NF_ACCEPT;
                else
                   {
                   printk("catch one");
                   return NF_DROP;
                    } 
                }           
             break;
		/*对于联合处理模式，是在上面的基础上进行修改的，分别有s_sign和u_sign来作为比较量，每进入一次联合甄别那么s_sign加一，若符合该条规则则u_sign加一，最后跳出联合过滤的时候，倘若两者相等，
			  那么判断这个包符合联合过滤的规则*/
      case 41:
            s_sign++;
            if((ip_s[0]==p->num[0]&&
                ip_s[1]==p->num[1]&&
                ip_s[2]==p->num[2]&&
                ip_s[3]==p->num[3])
             ||(ip_d[0]==p->num[0]&&
                ip_d[1]==p->num[1]&&
                ip_d[2]==p->num[2]&&
                ip_d[3]==p->num[3]))
                {
                  u_sign++;
                  }
          
       
            
             if(p->next==NULL||
               (p->next->mod!=41&&
                p->next->mod!=42&&
                p->next->mod!=43))
                 {
                 if(u_sign==s_sign)
                    {
                      if(p->p=='*')
                        return NF_ACCEPT;
                      else
                        return NF_DROP;
                      }
                 else
                     {
                      u_sign=0;
                      s_sign=0;
                     }
               
                 }
                   

             break;
      case 42:
             s_sign++;
             if(ip_header->protocol==p->pro)
                  u_sign++;
         
              
              if(p->next==NULL||
               (p->next->mod!=41&&
                p->next->mod!=42&&
                p->next->mod!=43))
                 {
                  if(u_sign==s_sign)
                    {
                      if(p->p=='*')
                        return NF_ACCEPT;
                      else
                        return NF_DROP;
                     
                      }
                  else
                     {
                      u_sign=0;
                      s_sign=0;
                     }
              
                 }
             break;
      case 43:
            s_sign++;
            if(p->a>payload_len)
                      break;
            if(payload_len!=0)
            {

            for(i=1;i<p->a;i++)
                   x++;
            for(i=p->a;i<=p->b&&i<=payload_len;i++)
                 { 
                  if((int)*x>=(int)p->c&&(int)*x<=(int)p->d)
                         x++;
                   else
                       break;
                   }
          
            if(i>p->b||i>payload_len)
               { 
                u_sign++;
                }
                  
          }
          else
              break;  
        
             if(p->next==NULL||
               (p->next->mod!=41&&
                p->next->mod!=42&&
                p->next->mod!=43))
                 {
                   if(u_sign==s_sign)
                     {
                       if(p->p=='*')
                         return NF_ACCEPT;
                       else
                         return NF_DROP;
                      }
                   else
                     {
                      u_sign=0;
                      s_sign=0;
                     }
              
                  }
                
             break; 



    }
  p=p->next;

  }
     return NF_ACCEPT;

}



/* 注册 */
static int hook_init(void)
 {
        printk("hook_init()======================\n");
        nf_register_hook(&pre_routing_ops);
        nf_register_hook(&post_routing_ops);
        return 0;
     }

static void hook_exit(void)
{
     printk("hook_exit()=====================\n");
     nf_unregister_hook(&pre_routing_ops);
     nf_unregister_hook(&post_routing_ops);
     LinkList *p,*q;
     p=head;
     while(p!=NULL)//清除规则空间
       {
          q=p->next;
          kfree(p);
          p=q;
      }
 }
 
module_init(hook_init);//模块注册函数
module_exit(hook_exit);//模块退出函数
