#include <gtk/gtk.h>
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include<malloc.h>
#include <memory.h>
//#include"fun.c"
#include"SM3.c"
#include <netinet/in.h>
#include <arpa/inet.h>
#include<sys/types.h>
#include<stddef.h>
#include<regex.h>


#define myport 3309 
#define buffer_length 1024
#define IDS_L 50+1
#define IDC_L 50+1
#define Random_L 16+1
#define doubleRandom_L 16*2+1//33
#define Hash_L 32+1
#define sendID_L 16+1
#define receiveID_L 16+1
typedef unsigned char byte;
typedef unsigned short word;
typedef unsigned int dword;


typedef struct
{
	byte *user;
	byte *passwd;
}ARG;
typedef struct
{
	word version;//0x01
	word XDcode;//0xA105
	word reqType;//0x12
	word authType;//0x02
	word step;//C-M 0x01;M-C 0x02
}PwAu_Header_CM, PwAu_Header_MC;

typedef struct {
	dword IDC_len;
	byte IDC[IDC_L];
	byte HashPw[Hash_L];
}PwAu_Body_CM;

typedef struct {
	dword resultCode;
}PwAu_Body_MC;




int check_endian() {
	int i = 0x12345678;
	char *c = (char *)&(i);
	return (*c == 0x12);
}

//int 类型大小端转化
dword BLEndianUint32(dword value)
{
	return ((value & 0x000000FF) << 24) | ((value & 0x0000FF00) << 8) | ((value & 0x00FF0000) >> 8) | ((value & 0xFF000000) >> 24);
}
//short 类型大小端转化
unsigned short BLEndianUshort(unsigned short value)
{
	return ((value & 0x00FF) << 8) | ((value & 0xFF00) >> 8);
}

void Send_PABCM(PwAu_Body_CM * p, char * buf) {
	if (check_endian()) {
		memcpy(buf, p, sizeof(PwAu_Body_CM));
	}
	else
	{
		PwAu_Body_CM *tmp = (PwAu_Body_CM*)malloc(sizeof(PwAu_Body_CM));
		tmp->IDC_len = BLEndianUint32(p->IDC_len);
		memcpy(tmp->IDC, p->IDC, IDC_L);
		memcpy(tmp->HashPw, p->HashPw, Hash_L);
		memcpy(buf, tmp, sizeof(PwAu_Body_CM));
printf("tmp->IDC:%s\n",tmp->IDC);

		free(tmp);
	}
}

void Send_PAHCM(PwAu_Header_CM * p, char * buf) {

	if (check_endian()) {
		memcpy(buf, p, sizeof(PwAu_Header_CM));
	}
	else
	{
		PwAu_Header_CM *tmp = (PwAu_Header_CM*)malloc(sizeof(PwAu_Header_CM));
		tmp->version = BLEndianUshort(p->version);
		tmp->XDcode = BLEndianUshort(p->XDcode);
		tmp->reqType = BLEndianUshort(p->reqType);
		tmp->authType = BLEndianUshort(p->authType);
		tmp->step = BLEndianUshort(p->step);
		memcpy(buf, tmp, sizeof(PwAu_Header_CM));
printf("步骤:%x\n",tmp->step);
		free(tmp);
	}
}
void Recv_PABMC(PwAu_Body_MC * p, char * buf) {
	memcpy(p, buf, sizeof(PwAu_Body_MC));
	if (!check_endian()) {
		p->resultCode = BLEndianUshort(p->resultCode);
	}
}
void Recv_PAHCM(PwAu_Header_CM * p, char * buf) {
	memcpy(p, buf, sizeof(PwAu_Header_CM));
	if (!check_endian()) {
		p->version = BLEndianUshort(p->version);
		p->XDcode = BLEndianUshort(p->XDcode);
		p->reqType = BLEndianUshort(p->reqType);
		p->authType = BLEndianUshort(p->authType);
		p->step = BLEndianUshort(p->step);
	}
}

void Recv_PAHMC(PwAu_Header_MC * p, char * buf) {
	Recv_PAHCM(p, buf);
}

//初始化函数
PwAu_Header_CM Init_PAHCM(PwAu_Header_CM p) {
	p.version = 0x01;
	p.XDcode = 0xA105;
	p.reqType = 0x12;
	p.authType = 0x02;
	p.step = 0x01;
	return p;
}

PwAu_Body_CM Init_PABCM(PwAu_Body_CM p) {
	p.IDC_len = 0;
	char name[] = { "weare" };
	return p;
}

/*
*功能：注册函数暂时用空函数代替
*
*/
void user_Register(GtkWidget *widget, gpointer *entry)
{
	gtk_main_quit();

}

/*
*功能：字符串位数不够，补零
*/
char *zeroize(char *iniStr) {
	//获取当前的出入字符串的长度
	int curr_len = strlen(iniStr);
	//计算此长度是否是128位的整数倍
	if ((curr_len) % 16 == 0)
	{
		//如果长度已经是128位的整数倍就不需要填充了
		return iniStr;
	}
	else
	{
		//计算填充后的长度
		int re = (128 - (curr_len * 8) % 128) / 8 + curr_len;
		//开辟填充后的对应大小的内存控件
		char *tmp = (char *)malloc(re);
		//内存置零
		memset(tmp, '0', re);
		//原值拷贝
		memcpy(tmp, iniStr, curr_len);
		//截断
		tmp[re] = '\0';
		return tmp;
	}
}
/*用户名正则判断函数*/
int Username_reg(char * buf) {
	int status;
	int cflags = REG_EXTENDED;//REG_EXTENDED 以功能更加强大的扩展正则表达式的方式进行匹配。
	regmatch_t pmatch[1];
	const size_t nmatch = 1;//是regmatch_t结构体数组的长度。
	regex_t reg;
	const char* pattern = "^[A-Za-z0-9]{6,20}+$";//验证由数字和26个英文字母组成的字符串
	regcomp(&reg, pattern, cflags);//编译正则模式
	status = regexec(&reg, buf, nmatch,pmatch, 0);//执行正则表达式和传入字符串的比较
	regfree(&reg);
	return status;

}
/*密码正则判断函数*/
int Pwd_reg(char * buf) {
	int status;
	int cflags = REG_EXTENDED;//REG_EXTENDED 以功能更加强大的扩展正则表达式的方式进行匹配。
	regmatch_t pmatch[1];
	const size_t nmatch = 1;//是regmatch_t结构体数组的长度。
	regex_t reg;
	const char* pattern = "^[0-9a-zA-Z!@#$%^&*]{6,20}$";//密码只能包含字母数字以及!@#$%^&* 这几个特殊字符组成并且必须为6-20位之间，不限制组合顺序
	regcomp(&reg, pattern, cflags);//编译正则模式
	status = regexec(&reg, buf, nmatch, pmatch,0);//执行正则表达式和传入字符串的比较
	regfree(&reg);
	return status;

}


void on_send(GtkWidget *widget, ARG *arg)
{
	int c_fd;
	int ret;
	struct sockaddr_in c_addr;
	PwAu_Header_CM pahcm;//生成数据头部 Init_PAHCM
	PwAu_Body_CM  pabcm;  //生成数据体 Innit_PABCM
	pahcm = Init_PAHCM(pahcm);//初始化 
							  // pabcm=Init_PABCM(pabcm);
        printf("步骤：%d\n",pahcm.step);
	 unsigned char *str1 = gtk_entry_get_text(GTK_ENTRY(arg->user));
	 unsigned char *str2 = gtk_entry_get_text(GTK_ENTRY(arg->passwd));
	//正则表达式来判断输入用户名、密码是否符合格式，用户名：字母和数字，密码：字母数字和特殊字符
	int User_comp,pwd_comp;
	User_comp = Username_reg(str1);
	pwd_comp = Pwd_reg(str2);
	if (User_comp == REG_NOMATCH || pwd_comp == REG_NOMATCH) 
		printf("用户名/密码输入格式不对\n");
	else if(User_comp==0 & pwd_comp==0) {

		unsigned char *str3;
		unsigned char idc[IDC_L], hashpw[Hash_L];
		str3 = SM3_256(str2,strlen(str2),hashpw);
		/*
		客户端将口令hash之后发送给中间件，此处需要SM3_256杂凑算法进行hash
		str3=SM3_256(ste2);
		int SM3_256(
		unsigned char *buf,
		int len,
		unsigned char *hash);

		*/
		//str3 = zeroize(str2);

		
		strcpy(pabcm.IDC, str1);
		strcpy(pabcm.HashPw, str3);

		gtk_main_quit();
		printf("UserName:%s\nPasswd:%0x\n", pabcm.IDC, pabcm.HashPw);
		printf("认证登录中,请稍等......\n");


		//创建  socket  
		c_fd = socket(AF_INET, SOCK_STREAM, 0);
		if (c_fd<0)
		{
			printf("cannot create communication socket\n");
			return;
		}
		c_addr.sin_family = AF_INET;
		c_addr.sin_port = htons(myport);
		// c_addr.sin_addr.s_addr=INADDR_ANY;
		c_addr.sin_addr.s_addr = inet_addr("192.168.1.116");

		//链接中间件 
		ret = connect(c_fd, (struct sockaddr*)&c_addr, sizeof(c_addr));
		if (ret == -1)
		{
			printf("cannot connect to the midlleware\n");
			close(c_fd);
			return;
		}

		unsigned char snd_buf[buffer_length] = { 0 };
		Send_PAHCM(&pahcm, snd_buf);
		Send_PABCM(&pabcm, snd_buf + sizeof(pahcm));

		//发送信息给中间件  
		send(c_fd, snd_buf, sizeof(pabcm)+sizeof(pahcm), 0);
		printf("send the message success\n");

		//接收中间件消息
		unsigned char rec_buf[buffer_length] = { 0 };
		int ret_recv = recv(c_fd, rec_buf, buffer_length, 0);
		if (ret_recv > 0) {
			printf("接收中间件成功\n");
			PwAu_Header_MC  pahmc;
			PwAu_Body_MC  pabmc;
			Recv_PAHMC(&pahmc, rec_buf);
			Recv_PABMC(&pabmc, rec_buf + sizeof(pahmc));

			printf("%d\n", pabmc.resultCode);
			return;

		}

		close(c_fd);



	}

	


}
/*  设置窗口背景        */

static void change_background(GtkWidget*widget,int w,int h,const gchar*path)
{
	gtk_widget_set_app_paintable(widget,TRUE); //允许窗口可以绘图
	gtk_widget_realize(widget);
	
	/*更改背景图时，图片会重叠
     * 这时要手动调用下面的函数，让窗口绘图区域失效，产生窗口重绘制事件
	*/
	gtk_widget_queue_draw(widget);
	
	GdkPixbuf *src_pixbuf=gdk_pixbuf_new_from_file(path,NULL);//创建图片资源对象
	//w,h 是指定图片的宽度和高度
	GdkPixbuf *dst_pixbuf=gdk_pixbuf_scale_simple(src_pixbuf,w,h,GDK_INTERP_BILINEAR); 
	GdkPixmap *pixmap=NULL;
	
	/*创建pixmap图像
	 128:0~255，透明到不透明 
	*/
	gdk_pixbuf_render_pixmap_and_mask(dst_pixbuf,&pixmap,NULL,128) ;
	//通过pixmap给widget设置一个背景图，最后一个参数必须为FALSE
	gdk_window_set_back_pixmap(widget->window,pixmap,FALSE);
	 
	 //释放资源
	 g_object_unref(src_pixbuf);
	 g_object_unref(dst_pixbuf);
	 g_object_unref(pixmap);
}




int main(int argc, char **argv)
{
	GtkWidget *win;
	GtkWidget *vbox;
	GtkWidget *hbox;
	GtkWidget *label;
	GtkWidget *button;
	GtkWidget *sep;
	GtkWidget *user;
	GtkWidget *passwd;
	ARG arg;
	//初始化 
	gtk_init(&argc, &argv);
	win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title(GTK_WINDOW(win), "登录界面");
	gtk_widget_set_size_request(win, 350, 180);//设置窗口大小 
	gtk_window_set_resizable(GTK_WINDOW(win), FALSE);//固定窗口大小 
	gtk_window_set_position(GTK_WINDOW(win), GTK_WIN_POS_CENTER);//设置窗口在显示屏的位置 
	change_background(win, 350, 200, "image.jpg");//设置窗口背景

	gtk_container_set_border_width(GTK_CONTAINER(win), 20);
	g_signal_connect(G_OBJECT(win), "destroy", G_CALLBACK(gtk_main_quit), NULL);
	vbox = gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(win), vbox);

	hbox = gtk_hbox_new(FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 5);
	label = gtk_label_new("用户名:");
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 5);
	user = gtk_entry_new();
        gtk_entry_set_max_length(GTK_ENTRY(user), 20);// 设置行编辑内容的最大长度
	gtk_box_pack_start(GTK_BOX(hbox), user, FALSE, FALSE, 5);
	
	button = gtk_button_new_with_label("注册账号");
	//label=gtk_label_new("注册账号");
	gtk_box_pack_start(GTK_BOX(hbox), button, FALSE, FALSE, 5);
	g_signal_connect(G_OBJECT(label), "clicked", G_CALLBACK(user_Register), NULL);

	hbox = gtk_hbox_new(FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 5);
	label = gtk_label_new("密  码: ");
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 5);
	passwd = gtk_entry_new();
	gtk_entry_set_visibility(GTK_ENTRY(passwd), FALSE); //设置输入密码时不会显示输入的字符
	gtk_entry_set_max_length(GTK_ENTRY(passwd), 20);//  设置行编辑内容的最大长度
	gtk_box_pack_start(GTK_BOX(hbox), passwd, FALSE, FALSE, 5);

	//button=gtk_button_new_with_label("找回密码");  
	label = gtk_label_new("找回密码");
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 5);

	sep = gtk_hseparator_new();
	gtk_box_pack_start(GTK_BOX(vbox), sep, FALSE, FALSE, 5);
	button = gtk_button_new_with_label("登  录");
	gtk_box_pack_start(GTK_BOX(vbox), button, FALSE, FALSE, 5);

	arg.user = (char*)user;
	arg.passwd = (char*)passwd;
	g_signal_connect(passwd, "activate", G_CALLBACK(on_send), &arg);
	g_signal_connect(G_OBJECT(button), "clicked", G_CALLBACK(on_send), &arg);
	gtk_widget_show_all(win);
	gtk_main();
	return 0;
}

