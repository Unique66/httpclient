package com.test.httpclient.util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.entity.mime.HttpMultipartMode;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.alibaba.fastjson.JSON;

/**
 * http网络请求工具类
 * @ClassName: WebUtils   
 */
public class WebUtils {

	private static Logger logger = LoggerFactory.getLogger(WebUtils.class);

	private static String PROXY_IP = "10.0.60.1";
	private static int PROXY_PORT = 8080;
	private static String PROXY_DOMAIN = "zzz";
	private static String PROXY_USER = "zzz";
	private static String PROXY_PASS = "zzz";
	private static boolean PROXY_USER_CHECK = true;
	

	static {
		
		String propStr = null;
		if ((propStr = SystemDataUtil.get("http.proxy.ip")) != null) {
			PROXY_IP = propStr;
		}
		if ((propStr = SystemDataUtil.get("http.proxy.port")) != null) {
			PROXY_PORT = Integer.parseInt(propStr);
		}
		if ((propStr = SystemDataUtil.get("http.proxy.domain")) != null) {
			PROXY_DOMAIN = propStr;
		}
		if ((propStr = SystemDataUtil.get("http.proxy.user")) != null) {
			PROXY_USER = propStr;
		}
		if ((propStr = SystemDataUtil.get("http.proxy.pass")) != null) {
			PROXY_PASS = propStr;
		}
		if ((propStr = SystemDataUtil.get("http.proxy.user_check")) != null) {
			PROXY_USER_CHECK = Boolean.parseBoolean(propStr);
		}
	}
	
	
	
	
	/**
	 * 向拼接好的URL发送Get请求
	 */
	public static String httpGet(String url) throws Exception {
		return httpGetWithParams(url, null);
	}

	/**
	 * 向拼接好的URL发送Get请求
	 */
	public static String httpsGet(String url) throws Exception {
		return httpsGetWithParams(url, null);
	}

	/**
	 * 向URL发送Get请求
	 * 
	 * @param url
	 *            接口地址
	 * @param params
	 *            接口参数
	 */
	public static String httpGetWithParams(String url, List<NameValuePair> params) throws Exception {
		return httpGetWithParams(url, params, "UTF-8", "UTF-8");
	}

	/**
	 * 向URL发送Get请求(https的方式)
	 * 
	 * @param url
	 *            接口地址
	 * @param params
	 *            接口参数
	 */
	public static String httpsGetWithParams(String url, List<NameValuePair> params) throws Exception {
		return httpsGetWithParams(url, params, "UTF-8", "UTF-8");
	}

	/**
	 * 向URL发送Get请求
	 * 
	 * @param url
	 *            接口地址
	 * @param params
	 *            接口参数
	 * @param uploadEncoding
	 *            参数编码格式
	 * @param responseEncoding
	 *            返回编码格式
	 */
	public static String httpGetWithParams(String url, List<NameValuePair> params, String uploadEncoding, String responseEncoding) throws Exception {

		CloseableHttpClient httpclient = null;
		try {

			httpclient = getHttpAndProxyHttpClient();

			HttpGet httpget = getHttpGet(url, params, uploadEncoding);

			HttpResponse response = httpclient.execute(httpget);

			return EntityUtils.toString(response.getEntity(), responseEncoding);

		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			return null;
		} finally {
			if (httpclient != null) {
				httpclient.close();
			}
		}
	}

	/**
	 * 向URL发送Get请求(https的方式)
	 * 
	 * @param url
	 *            接口地址
	 * @param params
	 *            接口参数
	 * @param uploadEncoding
	 *            参数编码格式
	 * @param responseEncoding
	 *            返回编码格式
	 */
	public static String httpsGetWithParams(String url, List<NameValuePair> params, String uploadEncoding, String responseEncoding) throws Exception {

		CloseableHttpClient httpclient = null;
		try {

			httpclient = getHttpsAndProxyHttpClient();

			HttpGet httpget = getHttpGet(url, params, uploadEncoding);

			HttpResponse response = httpclient.execute(httpget);

			return EntityUtils.toString(response.getEntity(), responseEncoding);

		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			return null;
		} finally {
			if (httpclient != null) {
				httpclient.close();
			}
		}
	}

	public static String httpPost(String url) throws Exception {
		return httpPostWithParams(url, null);
	}

	public static String httpsPost(String url) throws Exception {
		return httpsPostWithParams(url, null);
	}

	public static String httpPostWithParams(String url, List<NameValuePair> params) throws Exception {
		return httpPostWithParams(url, params, "UTF-8", "UTF-8");
	}

	public static String httpsPostWithParams(String url, List<NameValuePair> params) throws Exception {
		return httpsPostWithParams(url, params, "UTF-8", "UTF-8");
	}

	public static String httpPostWithParams(String url, List<NameValuePair> params, String uploadEncoding, String responseEncoding) throws Exception {

		CloseableHttpClient httpclient = null;

		try {
			httpclient = getHttpAndProxyHttpClient();
			HttpPost post = getHttpPost(url, params, uploadEncoding);
			if (params != null) {
				post.setEntity(new UrlEncodedFormEntity(params, uploadEncoding));
			}
			HttpResponse response = httpclient.execute(post);
			return EntityUtils.toString(response.getEntity(), responseEncoding);
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			return null;
		} finally {
			if (httpclient != null) {
				httpclient.close();
			}
		}
	}

	public static String httpsPostWithParams(String url, List<NameValuePair> params, String uploadEncoding, String responseEncoding) throws Exception {

		CloseableHttpClient httpclient = null;

		try {
			httpclient = getHttpsAndProxyHttpClient();
			HttpPost post = getHttpPost(url, params, uploadEncoding);
			if (params != null) {
				post.setEntity(new UrlEncodedFormEntity(params, uploadEncoding));
			}
			HttpResponse response = httpclient.execute(post);
			return EntityUtils.toString(response.getEntity(), responseEncoding);
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			return null;
		} finally {
			if (httpclient != null) {
				httpclient.close();
			}
		}
	}
	
	public static String httpsPostWithParamsAon(String url, Map<String, String> params,Map<String, String> headers,String body, String uploadEncoding, String responseEncoding) throws Exception {
		CloseableHttpClient httpclient = null;
		try {
			//httpclient = getHttpsAndProxyHttpClient();
			//HttpPost post = getHttpPost(url, params, uploadEncoding);
			//if (params != null) {
			//	post.setEntity(new UrlEncodedFormEntity(params, uploadEncoding));
			//}
			// 采用绕过验证的方式处理https请求 
			SSLContext sc = SSLContext.getInstance("TLSv1.2");
			// 实现一个X509TrustManager接口，用于绕过验证，不用修改里面的方法
			X509TrustManager trustManager = new X509TrustManager() {
				@Override
				public void checkClientTrusted(java.security.cert.X509Certificate[] paramArrayOfX509Certificate, String paramString) throws CertificateException {
				}

				@Override
				public void checkServerTrusted(java.security.cert.X509Certificate[] paramArrayOfX509Certificate, String paramString) throws CertificateException {
				}

				@Override
				public java.security.cert.X509Certificate[] getAcceptedIssuers() {
					return null;
				}
			};

			sc.init(null, new TrustManager[] { trustManager }, null);
			
			SSLContext sslcontext = sc;
			// 设置协议http和https对应的处理socket链接工厂的对象
			Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory> create().register("http", PlainConnectionSocketFactory.INSTANCE).register("https", new SSLConnectionSocketFactory(sslcontext)).build();
			PoolingHttpClientConnectionManager connManager = new PoolingHttpClientConnectionManager(socketFactoryRegistry);
			connManager.setMaxTotal(400); // 连接池最大数量
			connManager.setDefaultMaxPerRoute(200); // 单个路径最大数量

			// 创建自定义的httpclient对象
			HttpClientBuilder httpClientBuilder = HttpClients.custom().setConnectionManager(connManager);

			// 请求配置信息
			RequestConfig defaultRequestConfig = null;

			if (PROXY_USER_CHECK) {
				// 使用代理
				logger.info("getHttpsAndProxyHttpClient: 使用代理");
				logger.info("PROXY_IP="+PROXY_IP+"  PROXY_PORT="+PROXY_PORT);
				// 请求配置
				HttpHost proxy = new HttpHost(PROXY_IP, PROXY_PORT);
				defaultRequestConfig = RequestConfig.custom().setSocketTimeout(50000).setConnectTimeout(55000).setConnectionRequestTimeout(55000).setStaleConnectionCheckEnabled(true).setProxy(proxy).build();

				// 创建认证，并设置认证范围
				CredentialsProvider credsProvider = new BasicCredentialsProvider();
				// 可以访问的范围
				AuthScope authScope = new AuthScope(PROXY_IP, PROXY_PORT);
				// 用户名和密码
				UsernamePasswordCredentials usernamePasswordCredentials = new UsernamePasswordCredentials(PROXY_USER, PROXY_PASS);
				credsProvider.setCredentials(authScope, usernamePasswordCredentials);
				httpClientBuilder.setDefaultCredentialsProvider(credsProvider);

			} else {
				// 不使用代理
				logger.info("getHttpAndProxyHttpClient: 不使用代理");

				defaultRequestConfig = RequestConfig.custom().setSocketTimeout(50000).setConnectTimeout(55000).setConnectionRequestTimeout(55000).setStaleConnectionCheckEnabled(true).build();
			}

			httpClientBuilder.setDefaultRequestConfig(defaultRequestConfig);
			CloseableHttpClient client = httpClientBuilder.build();
			httpclient = client;
			HttpPost post = new HttpPost(url);
			if (body != null) {
				post.setEntity(new StringEntity(body));
			}
			Set<String> headNames = headers.keySet();
			for (String headName : headNames) {
				post.addHeader(headName, headers.get(headName));
			}
			HttpResponse response = httpclient.execute(post);
			return EntityUtils.toString(response.getEntity(), responseEncoding);
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			return null;
		} finally {
			if (httpclient != null) {
				httpclient.close();
			}
		}
	}

	/**
	 * 发送http post请求
	 */
	public static String httpPostData(String url, String data, String uploadEncoding, String responseEncoding) throws Exception {

		CloseableHttpClient httpclient = null;

		try {
			httpclient = getHttpAndProxyHttpClient();

			HttpPost httppost = getHttpPost(url, null, uploadEncoding);

			HttpEntity entity = new StringEntity(data, uploadEncoding);
			httppost.setEntity(entity);

			HttpResponse response = httpclient.execute(httppost);

			return EntityUtils.toString(response.getEntity(), responseEncoding);
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			return null;
		} finally {
			if (httpclient != null) {
				httpclient.close();
			}
		}
	}

	/**
	 * 发送https post请求
	 */
	public static String httpsPostData(String url, String data, String uploadEncoding, String responseEncoding) throws Exception {

		CloseableHttpClient httpclient = null;

		try {
			httpclient = getHttpsAndProxyHttpClient();

			HttpPost httppost = getHttpPost(url, null, uploadEncoding);

			HttpEntity entity = new StringEntity(data, uploadEncoding);
			httppost.setEntity(entity);

			HttpResponse response = httpclient.execute(httppost);

			return EntityUtils.toString(response.getEntity(), responseEncoding);
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			return null;
		} finally {
			if (httpclient != null) {
				httpclient.close();
			}
		}
	}

    /**
     * 发送http post请求，可携带头信息参数
     */
    public static String httpPostDataWithHeader(String url, String data, String uploadEncoding, String responseEncoding, Map<String, String> headers) throws Exception {

        CloseableHttpClient httpclient = null;

        try {
            Long date1 = System.currentTimeMillis();
            httpclient = getHttpAndProxyHttpClient();

            HttpPost httppost = getHttpPost(url, null, uploadEncoding);
            HttpEntity entity = new StringEntity(data, uploadEncoding);
            httppost.setEntity(entity);

            // 添加header
            if (headers != null) {
                addHeader(httppost, headers);
            }

            HttpResponse response = httpclient.execute(httppost);
            Long date2 = System.currentTimeMillis();
            Long sub = date2 - date1;
            logger.info("调用" + url + " 接口使用时间：" + sub + "ms");
            return EntityUtils.toString(response.getEntity(), responseEncoding);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            return null;
        } finally {
            if (httpclient != null) {
                httpclient.close();
            }
        }
    }

    /**
     * 发送https post请求，可携带头信息参数
     */
    public static String httpsPostDataWithHeader(String url, String data, String uploadEncoding, String responseEncoding, Map<String, String> headers) throws Exception {

        CloseableHttpClient httpclient = null;

        try {
            Long date1 = System.currentTimeMillis();
            httpclient = getHttpsAndProxyHttpClient();

            HttpPost httppost = getHttpPost(url, null, uploadEncoding);
            HttpEntity entity = new StringEntity(data, uploadEncoding);
            httppost.setEntity(entity);

            // 添加header
            if (headers != null) {
                addHeader(httppost, headers);
            }

            HttpResponse response = httpclient.execute(httppost);
            Long date2 = System.currentTimeMillis();
            Long sub = date2 - date1;
            logger.info("调用" + url + " 接口使用时间：" + sub + "ms");
            return EntityUtils.toString(response.getEntity(), responseEncoding);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            return null;
        } finally {
            if (httpclient != null) {
                httpclient.close();
            }
        }
    }

	/**
	 * http的方式json格式参数请求接口
	 */
	public static String httpPostJsonData(String url, String data, String uploadEncoding, String responseEncoding) throws Exception {

		CloseableHttpClient httpclient = null;

		try {
			httpclient = getHttpAndProxyHttpClient();

			HttpPost httppost = new HttpPost(url);
			httppost.addHeader("Content-type", "application/json; charset=utf-8");
			StringEntity entity = new StringEntity(data, Charset.forName("UTF-8"));

			httppost.setHeader("Accept", "application/json");
			httppost.setEntity(entity);

			HttpResponse response = httpclient.execute(httppost);

			return EntityUtils.toString(response.getEntity(), responseEncoding);
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			return null;
		} finally {
			if (httpclient != null) {
				httpclient.close();
			}
		}
	}

	/**
	 * https的方式json格式参数请求接口
	 */
	public static String httpsPostJsonData(String url, String data, String uploadEncoding, String responseEncoding) throws Exception {

		CloseableHttpClient httpclient = null;

		try {
			httpclient = getHttpsAndProxyHttpClient();

			HttpPost httppost = new HttpPost(url);
			httppost.addHeader("Content-type", "application/json; charset=utf-8");
			StringEntity entity = new StringEntity(data, Charset.forName("UTF-8"));
			httppost.setHeader("Accept", "application/json");
			httppost.setEntity(entity);

			HttpResponse response = httpclient.execute(httppost);

			return EntityUtils.toString(response.getEntity(), responseEncoding);
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			return null;
		} finally {
			if (httpclient != null) {
				httpclient.close();
			}
		}
	}

	/**
	 * 调用环信接口，需要传入环信的token
	 * 
	 * @param url
	 * @param data
	 * @param huanxinToken
	 * @param uploadEncoding
	 * @param responseEncoding
	 */
	public static String postHuanxinJsonData(String url, String data, String huanxinToken, String uploadEncoding, String responseEncoding) throws Exception {

		CloseableHttpClient httpclient = null;

		try {
			httpclient = getHttpsAndProxyHttpClient();

			HttpPost httppost = new HttpPost(url);
			httppost.addHeader("Content-type", "application/json; charset=utf-8");
			StringEntity entity = new StringEntity(data, Charset.forName("UTF-8"));
			httppost.setHeader("Accept", "application/json");

			if (null != huanxinToken && !"".equals(huanxinToken)) {
				httppost.setHeader("Authorization", "Bearer " + huanxinToken);
				httppost.setHeader("restrict-access", "true");
			}

			httppost.setEntity(entity);

			HttpResponse response = httpclient.execute(httppost);

			return EntityUtils.toString(response.getEntity(), responseEncoding);
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			return null;
		} finally {
			if (httpclient != null) {
				httpclient.close();
			}
		}
	}

	/**
	 * 创建get http请求，可携带请求头信息参数
	 */
	public static String getData(String url, String uploadEncoding, String responseEncoding, Map<String, String> headers) throws Exception {

		CloseableHttpClient httpclient = null;

		try {
			httpclient = getHttpAndProxyHttpClient();

			HttpGet httpget = new HttpGet(url);

			if (headers != null) {
				addHeader(httpget, headers);
			}

			HttpResponse response = httpclient.execute(httpget);

			return EntityUtils.toString(response.getEntity(), responseEncoding);
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			return null;
		} finally {
			if (httpclient != null) {
				httpclient.close();
			}
		}
	}

	/**
	 * 添加请求头信息
	 */
	private static void addHeader(HttpRequestBase request, Map<String, String> headers) {
		if (headers == null || headers.isEmpty()) {
			return;
		}
		Set<String> headNames = headers.keySet();
		for (String headName : headNames) {
			request.addHeader(headName, headers.get(headName));
		}
	}

	/**
	 * 获取HttpPost
	 */
	private static HttpGet getHttpGet(String url, List<NameValuePair> params, String encode) {
		StringBuffer buf = new StringBuffer(url);
		if (params != null) {
			// 地址增加?或者&
			String flag = (url.indexOf('?') == -1) ? "?" : "&";
			for (NameValuePair nameValuePair : params) {
				// 参数连接符
				buf.append(flag);
				// name
				buf.append(nameValuePair.getName());
				buf.append("=");
				try {
					String param = nameValuePair.getValue();
					if (param == null) {
						param = "";
					}
					buf.append(URLEncoder.encode(param, encode));
				} catch (UnsupportedEncodingException e) {
					logger.error("URLEncoder Error,encode=" + encode + ",param=" + nameValuePair.getValue(), e);
				}
				flag = "&";
			}
		}
		HttpGet httpGet = new HttpGet(buf.toString());
		return httpGet;
	}

	/**
	 * 获取HttpPost
	 */
	private static HttpPost getHttpPost(String url, List<NameValuePair> params, String encode) {
		HttpPost httpPost = new HttpPost(url);
		if (params != null) {
			try {
				UrlEncodedFormEntity entity = new UrlEncodedFormEntity(params, encode);
				httpPost.setEntity(entity);
			} catch (UnsupportedEncodingException e) {
				logger.error("UrlEncodedFormEntity Error,encode=" + encode + ",form=" + params, e);
			}
		}
		return httpPost;
	}

	/**
	 * http 下载文件
	 * 
	 * @param targetUrl
	 *            资源地址
	 * @param destFileLocation
	 *            文件保存目录
	 * @param token
	 *            调用接口的授权token
	 * @param msgType
	 *            判断下载的文件的类型 img 为图片
	 * @return destFileName 文件的保存路径
	 */
	public static String httpDownloadFile(String targetUrl, String destFileLocation, String token, String msgType) throws Exception {

		logger.info("http 下载文件");
		CloseableHttpClient client = getHttpAndProxyHttpClient();

		try {
			// 请求地址
			HttpGet httpget = new HttpGet(targetUrl);

			// 如果接口调用有Authorization认证token传入，此种情况是从环信下载文件
			if (null != token && !"".equals(token)) {
				httpget.setHeader("Authorization", "Bearer " + token);
				httpget.setHeader("restrict-access", "true");
				// Accept: application/octet-stream
				httpget.setHeader("Accept", "application/octet-stream");
			}

			// 执行请求
			CloseableHttpResponse response = client.execute(httpget);
			// 获取响应对象
			HttpEntity entity = response.getEntity();
			// 获取数据流
			InputStream in = entity.getContent();
			// 打印响应状态
			String statusLine = response.getStatusLine().toString();
			logger.info("响应状态statusLine：" + statusLine);

			// 获取响应头
			String contentType = response.getHeaders("Content-Type")[0].getValue();
			logger.info("contentType:" + contentType);

			// 例如图片为image/jpeg 高清语音素材为voice/speex 普通语音素材为 voice/amr
			String namePrefix = contentType.split("/")[0];
			String nameSuffix = contentType.split("/")[1];

			// 防止下载的文件重复,使用uuid命名
			UUID fileNameUUID = UUID.randomUUID();
			String destFileName = "";

			// 为了显示正常 jpeg改为jpg后缀
			if (null != nameSuffix && "jpeg".equals(nameSuffix.toLowerCase())) {
				nameSuffix = "jpg";
			}

			// 从环信下载是二进制流的方式
			if (contentType.contains("application/octet-stream")) {
				logger.info("从环信下载文件，二进制流的方式");
				if (null != msgType && "img".equals(msgType)) {
					nameSuffix = "jpg";
				}
				// 此时不知道文件的类型，也不知道文件后缀
				destFileName = destFileLocation + "/" + namePrefix + fileNameUUID + "." + nameSuffix;
			} else {
				logger.info("没有返回文件流，下载失败：" + response.getEntity().getContent().toString());
				// 此时不知道文件的类型，也不知道文件后缀
				destFileName = destFileLocation + "/" + namePrefix + fileNameUUID + "." + nameSuffix;
			}

			// 判断是否请求成功
			if (statusLine.contains("200") && statusLine.contains("OK")) {
				logger.info("请求成功");
				// 请求成功
				try {
					File file = new File(destFileName);
					// 使用FileOutputStream，如果用OutputStream.write(buff)的话，图片会失真
					FileOutputStream fout = new FileOutputStream(file);
					int l = -1;
					byte[] tmp = new byte[1024];
					while ((l = in.read(tmp)) != -1) {
						fout.write(tmp, 0, l);
					}
					fout.flush();
					fout.close();

					return file.getCanonicalPath();

				} catch (Exception e) {
					e.printStackTrace();
					logger.info("下载并保存文件失败");
					return "fail";
				} finally {
					// 关闭低层流。
					in.close();
				}
			} else {
				logger.info("请求失败");
				return "fail";
			}

		} catch (Exception e1) {
			e1.printStackTrace();
			logger.info("下载并保存文件失败");
			return "fail";
		} finally {
			client.close();
		}
	}

	/**
	 * https 下载文件
	 * 
	 * @param targetUrl
	 *            资源地址
	 * @param destFileLocation
	 *            文件保存目录
	 * @param token
	 *            调用接口的授权token
	 * @return destFileName 保存的文件路径
	 */
	public static String httpsDownloadFile(String targetUrl, String destFileLocation, String token, String msgType) throws Exception {

		logger.info("https 下载文件");

		CloseableHttpClient client = getHttpsAndProxyHttpClient();

		try {
			// 请求地址
			HttpGet httpget = new HttpGet(targetUrl);

			// 如果接口调用有Authorization授权token传入
			if (null != token && !"".equals(token)) {
				httpget.setHeader("Authorization", "Bearer " + token);
				httpget.setHeader("restrict-access", "true");
				httpget.setHeader("Accept", "application/octet-stream");
			}

			// 执行请求
			CloseableHttpResponse response = client.execute(httpget);
			// 获取响应对象
			HttpEntity entity = response.getEntity();
			// 获取数据流
			InputStream in = entity.getContent();
			// 打印响应状态
			String statusLine = response.getStatusLine().toString();
			logger.info("响应状态statusLine：" + statusLine);

			// 获取响应头
			String contentType = response.getHeaders("Content-Type")[0].getValue();
			logger.info("contentType:" + contentType);

			// 例如图片为image/jpeg 高清语音素材为voice/speex 普通语音素材为 voice/amr
			String namePrefix = contentType.split("/")[0];
			String nameSuffix = contentType.split("/")[1];

			// 防止下载的文件重复,使用uuid命名
			UUID fileNameUUID = UUID.randomUUID();
			String destFileName = "";

			// 为了显示正常 jpeg改为jpg后缀
			if (null != nameSuffix && "jpeg".equals(nameSuffix.toLowerCase())) {
				nameSuffix = "jpg";
			}
			// 从环信下载是二进制流的方式
			if (contentType.contains("application/octet-stream")) {
				logger.info("从环信下载文件，二进制流的方式");
				if (null != msgType && "img".equals(msgType)) {
					nameSuffix = "jpg";
				}
				// 此时不知道文件的类型，也不知道文件后缀
				destFileName = destFileLocation + "/" + namePrefix + fileNameUUID + "." + nameSuffix;
			} else {
				logger.info("没有返回文件流，下载失败：" + response.getEntity().getContent().toString());
				// 此时不知道文件的类型，也不知道文件后缀
				destFileName = destFileLocation + "/" + namePrefix + fileNameUUID + "." + nameSuffix;
			}

			// 判断是否请求成功
			if (statusLine.contains("200") && statusLine.contains("OK")) {
				logger.info("请求成功");
				// 请求成功
				try {
					File file = new File(destFileName);
					// 使用FileOutputStream，如果用OutputStream.write(buff)的话，图片会失真
					FileOutputStream fout = new FileOutputStream(file);
					int l = -1;
					byte[] tmp = new byte[1024];
					while ((l = in.read(tmp)) != -1) {
						fout.write(tmp, 0, l);
					}
					fout.flush();
					fout.close();

					return file.getCanonicalPath();

				} catch (Exception e) {
					e.printStackTrace();
					logger.info("下载并保存文件失败");
					return "fail";
				} finally {
					// 关闭低层流。
					in.close();
				}
			} else {
				logger.info("请求失败");
				return "fail";
			}

		} catch (Exception e1) {
			e1.printStackTrace();
			logger.info("下载并保存文件失败");
			return "fail";
		} finally {
			client.close();
		}
	}

	/**
	 * https 上传文件
	 * 
	 * @param targetUrl
	 *            上传地址
	 * @param destFileName
	 *            文件的保存位置
	 * @param token
	 *            调用接口的授权token
	 */
	public static String httpsUploadFile(String targetUrl, String destFileName, String token) throws Exception {

		CloseableHttpClient client = getHttpsAndProxyHttpClient();

		try {
			// 把一个普通参数和文件上传给下面这个地址 是一个servlet
			HttpPost httpPost = new HttpPost(targetUrl);

			// 如果接口调用有Authorization授权token传入
			if (null != token && !"".equals(token)) {
				// 上传文件到环信时
				httpPost.setHeader("restrict-access", "true");
				httpPost.setHeader("Authorization", "Bearer " + token);
			}

			File file = new File(destFileName);
			HttpEntity reqEntity = MultipartEntityBuilder.create().addBinaryBody("file", file, ContentType.APPLICATION_OCTET_STREAM, file.getName()).build();

			httpPost.setEntity(reqEntity);

			logger.info("发起请求的页面地址 :" + httpPost.getRequestLine());

			// 发起请求 并返回请求的响应
			CloseableHttpResponse response = client.execute(httpPost);

			try {
				// 打印响应状态
				String statusLine = response.getStatusLine().toString();
				logger.info("响应状态statusLine：" + statusLine);

				// 判断是否请求成功
				if (statusLine.contains("200") && statusLine.contains("OK")) {

					logger.info("请求成功");
					// 获取响应对象
					HttpEntity resEntity = response.getEntity();
					if (resEntity != null) {
						// 打印响应长度
						logger.info("Response content length: " + resEntity.getContentLength());
						// 返回结果
						String result = EntityUtils.toString(resEntity, Charset.forName("UTF-8"));
						logger.info("Response content: " + result);
						// 销毁
						EntityUtils.consume(resEntity);
						return result;
					} else {
						logger.error("上传文件响应为空");
						return "fail";
					}
				} else {
					logger.error("请求失败");
					return "fail";
				}

			} catch (Exception e2) {
				e2.printStackTrace();
				return "fail";
			} finally {
				response.close();
			}
		} catch (Exception e) {
			e.printStackTrace();
			return "fail";
		} finally {
			client.close();
		}
	}

	/**
	 * 绕过验证ssl验证
	 * 
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws KeyManagementException
	 */
	public static SSLContext createIgnoreVerifySSL() throws NoSuchAlgorithmException, KeyManagementException {

		SSLContext sc = SSLContext.getInstance("SSLv3");

		// 实现一个X509TrustManager接口，用于绕过验证，不用修改里面的方法
		X509TrustManager trustManager = new X509TrustManager() {
			@Override
			public void checkClientTrusted(java.security.cert.X509Certificate[] paramArrayOfX509Certificate, String paramString) throws CertificateException {
			}

			@Override
			public void checkServerTrusted(java.security.cert.X509Certificate[] paramArrayOfX509Certificate, String paramString) throws CertificateException {
			}

			@Override
			public java.security.cert.X509Certificate[] getAcceptedIssuers() {
				return null;
			}
		};

		sc.init(null, new TrustManager[] { trustManager }, null);
		return sc;
	}

	/**
	 * 获取https使用代理的请求配置
	 */
	private static CloseableHttpClient getHttpsAndProxyHttpClient() throws Exception {

		// 采用绕过验证的方式处理https请求
		SSLContext sslcontext = createIgnoreVerifySSL();
		// 设置协议http和https对应的处理socket链接工厂的对象
		Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory> create().register("http", PlainConnectionSocketFactory.INSTANCE).register("https", new SSLConnectionSocketFactory(sslcontext)).build();
		PoolingHttpClientConnectionManager connManager = new PoolingHttpClientConnectionManager(socketFactoryRegistry);
		connManager.setMaxTotal(400); // 连接池最大数量
		connManager.setDefaultMaxPerRoute(200); // 单个路径最大数量

		// 创建自定义的httpclient对象
		HttpClientBuilder httpClientBuilder = HttpClients.custom().setConnectionManager(connManager);

		// 请求配置信息
		RequestConfig defaultRequestConfig = null;

		if (PROXY_USER_CHECK) {
			// 使用代理
			logger.info("getHttpsAndProxyHttpClient: 使用代理");
			logger.info("PROXY_IP="+PROXY_IP+"  PROXY_PORT="+PROXY_PORT);
			// 请求配置
			HttpHost proxy = new HttpHost(PROXY_IP, PROXY_PORT);
			defaultRequestConfig = RequestConfig.custom().setSocketTimeout(50000).setConnectTimeout(55000).setConnectionRequestTimeout(55000).setStaleConnectionCheckEnabled(true).setProxy(proxy).build();

			// 创建认证，并设置认证范围
			CredentialsProvider credsProvider = new BasicCredentialsProvider();
			// 可以访问的范围
			AuthScope authScope = new AuthScope(PROXY_IP, PROXY_PORT);
			// 用户名和密码
			UsernamePasswordCredentials usernamePasswordCredentials = new UsernamePasswordCredentials(PROXY_USER, PROXY_PASS);
			credsProvider.setCredentials(authScope, usernamePasswordCredentials);
			httpClientBuilder.setDefaultCredentialsProvider(credsProvider);

		} else {
			// 不使用代理
			logger.info("getHttpAndProxyHttpClient: 不使用代理");

			defaultRequestConfig = RequestConfig.custom().setSocketTimeout(50000).setConnectTimeout(55000).setConnectionRequestTimeout(55000).setStaleConnectionCheckEnabled(true).build();
		}

		httpClientBuilder.setDefaultRequestConfig(defaultRequestConfig);

		CloseableHttpClient client = httpClientBuilder.build();
		return client;
	}

	/**
	 * 获取http使用代理的请求配置
	 */
	private static CloseableHttpClient getHttpAndProxyHttpClient() {

		// 创建连接池管理器
		PoolingHttpClientConnectionManager connManager = new PoolingHttpClientConnectionManager();
		connManager.setMaxTotal(400); // 连接池最大数量
		connManager.setDefaultMaxPerRoute(200); // 单个路径最大数量

		// 创建自定义的httpclient对象
		HttpClientBuilder httpClientBuilder = HttpClients.custom().setConnectionManager(connManager);

		// 请求配置信息
		RequestConfig defaultRequestConfig = null;

		if (PROXY_USER_CHECK) {
			// 使用代理
			logger.info("getHttpAndProxyHttpClient: 使用代理");
			logger.info("PROXY_IP="+PROXY_IP+"  PROXY_PORT="+PROXY_PORT);
			// 设置代理
			HttpHost proxy = new HttpHost(PROXY_IP, PROXY_PORT);// 代理的设置,依次是代理地址，代理端口号，协议类型
			defaultRequestConfig = RequestConfig.custom().setSocketTimeout(50000).setConnectTimeout(55000).setConnectionRequestTimeout(55000).setStaleConnectionCheckEnabled(true).setProxy(proxy).build();

			// 创建认证，并设置认证范围
			CredentialsProvider credsProvider = new BasicCredentialsProvider();
			// 可以访问的范围
			AuthScope authScope = new AuthScope(PROXY_IP, PROXY_PORT);
			// 用户名和密码
			UsernamePasswordCredentials usernamePasswordCredentials = new UsernamePasswordCredentials(PROXY_USER, PROXY_PASS);
			credsProvider.setCredentials(authScope, usernamePasswordCredentials);

			// 设置代理认证
			httpClientBuilder.setDefaultCredentialsProvider(credsProvider);
		} else {
			// 不使用代理
			logger.info("getHttpAndProxyHttpClient: 不使用代理");
			defaultRequestConfig = RequestConfig.custom().setSocketTimeout(50000).setConnectTimeout(55000).setConnectionRequestTimeout(55000).setStaleConnectionCheckEnabled(true).build();
		}

		httpClientBuilder.setDefaultRequestConfig(defaultRequestConfig);

		CloseableHttpClient client = httpClientBuilder.build();
		return client;
	}
	
	/**
	 * 上传微信临时素材
	 * @param url 
	 * @param access_token
	 * @param type 媒体文件类型
	 * @param file 媒体文件路径
	 * @param responseEncoding 字符编码
	 * @return
	 * @throws Exception
	 */
	
	public static String httpsPostUploadData(String url, String access_token, String type, String file,String responseEncoding) throws Exception {
		CloseableHttpClient httpclient = null;
		try {
			httpclient = getHttpsAndProxyHttpClient();
			
			MultipartEntityBuilder mBuilder = get_COMPATIBLE_Builder(responseEncoding);
			
			// 设置type
			mBuilder.addTextBody("type", type);
			// 设置access_token，
			mBuilder.addTextBody("access_token", access_token);
			
			// 这里就是我要上传到服务器的多媒体图片
			mBuilder.addBinaryBody(type, getFile(file),
					ContentType.APPLICATION_OCTET_STREAM, getFile(file).getName());
			
			// 建造我们的http多媒体对象
			HttpEntity httpEntity = mBuilder.build();
			// 得到一个post请求的实体
			HttpPost post = new HttpPost(url);
			post.addHeader("Connection", "keep-alive");
			post.addHeader("Accept", "*/*");
			post.addHeader("Content-Type", "multipart/form-data;boundary="
					+ getBoundaryStr("7da2e536604c8"));
			post.addHeader("User-Agent",
					"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0) ");
			
			// 给请求添加参数
			post.setEntity(httpEntity);
		
			// 执行请求并获得结果
			HttpResponse response = httpclient.execute(post);
		
			return EntityUtils.toString(response.getEntity(), responseEncoding);
		} finally {
			if (httpclient != null) {
				httpclient.close();
			}
		}
		
	}
	
    /**
     *  
     * @Description: http 下载文件
     * @author : qsnp220
     * @date : 2019年2月21日上午9:43:17
     * @param targetUrl
     * @param path
     * @return
     * @throws Exception
     */
     
    public static String httpDownloadFile(String targetUrl, String path) throws Exception {

        logger.info("http 下载文件："+targetUrl);
        CloseableHttpClient client = getHttpAndProxyHttpClient();

        try {
            // 请求地址
            HttpGet httpget = new HttpGet(targetUrl);

            // 执行请求
            CloseableHttpResponse response = client.execute(httpget);
            // 获取响应对象
            HttpEntity entity = response.getEntity();
            // 获取数据流
            InputStream in = entity.getContent();
            // 打印响应状态
            String statusLine = response.getStatusLine().toString();
            logger.info("响应状态statusLine：" + statusLine);

            // 判断是否请求成功
            if (statusLine.contains("200") && statusLine.contains("OK")) {
                // 请求成功
                try {
                    File file = new File(path);
                    // 使用FileOutputStream，如果用OutputStream.write(buff)的话，图片会失真
                    FileOutputStream fout = new FileOutputStream(file);
                    int l = -1;
                    byte[] tmp = new byte[1024];
                    while ((l = in.read(tmp)) != -1) {
                        fout.write(tmp, 0, l);
                    }
                    fout.flush();
                    fout.close();
                    System.out.println(file.getCanonicalPath());
                    return file.getCanonicalPath();
                } catch (Exception e) {
                    e.printStackTrace();
                    logger.info("下载并保存文件失败");
                    return "fail";
                } finally {
                    in.close();
                }
            } else {
                logger.info("请求失败");
                return "fail";
            }
        } catch (Exception e) {
            e.printStackTrace();
            logger.info("下载并保存文件失败");
            return "fail";
        } finally {
            client.close();
        }
    }
	
	private static MultipartEntityBuilder get_COMPATIBLE_Builder(String charSet) {
		MultipartEntityBuilder result = MultipartEntityBuilder.create();
		result.setBoundary(getBoundaryStr("7da2e536604c8"))
				.setCharset(Charset.forName(charSet))
				.setMode(HttpMultipartMode.BROWSER_COMPATIBLE);
		return result;
	}
	private static String getBoundaryStr(String str) {
		return "------------" + str;
	}
	private static File getFile(String path) {
		return new File(path);
	}

}
