import type { AnnouncementConfig } from "../types/announcementConfig";

export const announcementConfig: AnnouncementConfig = {
	// 公告标题，留空则走i18n默认标题
	title: "公告",

	// 公告内容
	content: "欢迎来到我的博客，本博客仅供学习交流使用，请严格遵守法律法规，未经授权严禁对真实目标进行扫描或攻击！",

	// 是否允许用户关闭公告
	closable: false,

	link: {
		// 启用链接
		enable: false,
		// 链接文本
		text: "了解更多",
		// 链接 URL
		url: "/about/",
		// 内部链接
		external: false,
	},
};
