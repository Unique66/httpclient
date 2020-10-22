package com.test.httpclient.util;

import java.io.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Properties;

/**
 * 系统标准数据,在sysdata.ini文件中存储,以标准property格式保存
 * 
 * @copyright 2013-4-12 GeneraliChina Co.Ltd All right reserved
 * @author chengxt
 * @history create Administrator 2013-4-12 上午9:52:40
 * @version 1.0
 */
public class SystemDataUtil {

	private static Properties props;// 资源文件保存

	/**
	 * 获取指定配置的值
	 * 
	 * @param key
	 *            配置
	 * @return 配置值
	 */
	public static String get(String key) {
		if (hasChaged()) {
			init();
		}
		String val = (String) props.get(key);
		if (val != null) {
			return val;
		} else {
			init();
			val = (String) props.getProperty(key);
			return val;
		}
	}

	/**
	 * 修改配置
	 * 
	 * @param key
	 * @param value
	 * @throws IOException
	 */
	public static void update(String key, String value) throws IOException {
		if (hasChaged()) {
			init();
		}
		synchronized (props) {
			StringBuffer infos = new StringBuffer();
			String line;

			SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
			if (props.containsKey(key)) {
				infos.append("#").append(sdf.format(new Date()))
						.append("  update ").append(key).append("  from ")
						.append(props.getProperty(key)).append(" to ")
						.append(value);
			} else {
				infos.append("#").append(sdf.format(new Date()))
						.append("  set ").append(key).append(" = ")
						.append(value);
			}
			infos.append("\n");

			File file = getFile();
			BufferedReader reader = new BufferedReader(new InputStreamReader(
					new FileInputStream(file)));
			while ((line = reader.readLine()) != null) {
				if (line.startsWith(key)) {
					infos.append(key).append("=").append(value).append("\n");
				} else {
					infos.append(line).append("\n");
				}
			}
			if (!props.containsKey(key)) {
				infos.append(key).append("=").append(value);
			}
			BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
					new FileOutputStream(file)));
			writer.write(infos.toString());
			writer.flush();
			writer.close();
			reader.close();
			init();
		}
	}

	// 初始化，加载配置文件
	private static void init() {
		if (props == null) {
			props = new Properties();
		}
		File file = getFile();
		if (file != null) {
			props.put("lastUpdateTime", file.lastModified());
			try {
				InputStream is = new FileInputStream(file);
				props.load(is);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	// 判断是否有更新
	private static Boolean hasChaged() {
		if (props == null) {
			return true;
		}
		File file = getFile();
		if (file != null
				&& file.lastModified() != ((Long) props.get("lastUpdateTime"))
						.longValue()) {
			return true;
		}
		return false;
	}

	// 获取配置文件
	private static File getFile() {
		String filePath = SystemDataUtil.class.getResource("/sysdata.ini")
				.getFile();
		File f = new File(filePath);
		if (f.isFile()) {
			return f;
		} else {
			return null;
		}
	}
}
