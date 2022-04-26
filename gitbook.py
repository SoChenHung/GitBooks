import requests
import re
import os
from lxml import etree

url = 'https://dmcxblue.gitbook.io'
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.60 Safari/537.36',
    'referer': url,
    'Cookie': 'amp_fef1e8=c3f025e1-ceb2-44ec-8e7c-41b56bd4f8f1R...1g17mv7jg.1g17n61ho.s.9.15'
}
ips = {
    '202.55.5.209:8090',
    '122.9.101.6:8888',
    '106.54.128.253:999',
    '118.163.120.181:58837',
    '115.218.2.9:9000'
}
# introduction
data_offset_key_list = []
introduction_text_list = []
# 父目录所在链接 去掉第一个
catalog_link_href_1 = []
# 父目录名字
catalog_name_1 = []
# 父目录列表
catalog_list_1 = []
# 图片保存地址
img_path = '../src/gitbook_img/'
class crawl_gitBook():
    def __init__(self):
        super(crawl_gitBook,self).__init__()

    #  获取所有父目录
    @staticmethod
    def getParentCatalog(urls, ip_list, header):
        e_obj = ""
        catalog_name = ''
        catalog_link = ''
        try:
            # 判断ip_list是否有数据
            len(ip_list) / len(ip_list)
        except ZeroDivisionError:
            print("[getParentCatalog]ERROR-->", ZeroDivisionError)
        else:
            for ip in ip_list:
                try:
                    response = requests.get(url=urls, proxies={'http': ip}, headers=header)
                except Exception as error:
                    print("[getParentCatalog]ERROR-->", error)
                else:
                    r_str = response.text
                    # 实例化etree对象
                    e_obj = etree.HTML(r_str)
                    # 获取文本内容
                    e_data = e_obj.xpath("//div[@dir='auto']/span//@data-offset-key")
                    # 获取所有父目录链接
                    e_href = e_obj.xpath("//div[@class='css-1dbjc4n r-11q2w3b r-1yzf0co']//@href")
                    counts = 0
                    for first_data in e_data:
                        data_offset_key_list.append(first_data)
                        if counts == 3:
                            break
                        counts += 1
                    for link in e_href:
                        catalog_link_href_1.append(link)
                    for link in catalog_link_href_1:
                        # print(len(link.split('/')))
                        lens = len(link.split('/'))
                        # 获取父目录名字
                        if lens == 3:
                            # print(link.split('/')[2])
                            catalog_name = link.split('/')[2]
                            catalog_link = url + link
                        elif lens == 4:
                            # print(link.split('/')[3])
                            catalog_name = link.split('/')[3]
                            catalog_link = url + link
                        # print(catalog_name,catalog_link)
                        catalog_dict_1 = {}.fromkeys(['catalog_name', 'catalog_link'])
                        catalog_dict_1['catalog_name'] = catalog_name
                        catalog_dict_1['catalog_link'] = catalog_link
                        catalog_list_1.append(catalog_dict_1)
                    break

        return e_obj

    # 爬取所有目录
    def start_spider(self, new_url, new_name, label_levels):
        # 所有内容
        text_data_list = []
        # 所有二级目录
        descendant_href_list = []
        # 放入标题等级标签
        text_data_list.append(label_levels)
        try:
            res = requests.get(url=new_url, headers=headers)
        except Exception as e:
            print("[start_spider]ERROR--->", e)
        else:
            res_str = res.text
            new_e_obj = etree.HTML(res_str)
            # 爬取网页文本内容
            # new_e_data = new_e_obj.xpath("//div[@dir='auto']/span//@data-offset-key")
            new_e_data = new_e_obj.xpath("//div[@data-key]/@data-key")
            try:
                new_e_data.pop(0)
            except Exception as e:
                print('[new_e_data]ERROR--->', e)
            for key in new_e_data:
                # actual_text = new_e_obj.xpath("//div[@dir='auto']//span[@data-offset-key='{}']//text()".format(key))
                # 普通文本
                actual_text = new_e_obj.xpath("//div[@data-key='{}']//text()".format(key))
                # strong文本
                strong_text = new_e_obj.xpath("//div[@data-key='{}']//strong//text()".format(key))
                # img
                img_src = new_e_obj.xpath("//div[@data-key='{}']//img/@src".format(key))
                href_link = new_e_obj.xpath("//div[@data-key]//a//text()")
                if len(actual_text) > 1:
                    for element in actual_text:
                        if href_link:
                            for link in href_link:
                                if link == element:
                                    _href = new_e_obj.xpath("//div[@data-key]//a/@href")
                                    text_data_list.append('[{}]({})'.format(element, _href[0]))
                                else:
                                    text_data_list.append(element)
                        else:
                            text_data_list.append(element)
                else:
                    if actual_text:
                        text_data_list.append(actual_text[0])
                if strong_text:
                    for s_text in strong_text:
                        if s_text in text_data_list:
                            text_data_list[text_data_list.index(s_text)] = '**{}**'.format(s_text)
                # if strong_text:
                #
                #     if strong_text[0] == actual_text[actual_text.index(strong_text[0])]:
                #         text_data_list[actual_text.index(strong_text[0])] = '**{}**'. \
                #             format(strong_text[0])
                # if actual_text:
                #     text_data_list.append(actual_text[0])
                # if strong_text:
                #     text_data_list.append(strong_text[0])
                if img_src:
                    numbers = 0
                    img_name = img_path + new_name + str(numbers) + '.jpg'
                    for img_link in img_src:
                        with open(img_name, 'wb') as f:
                            f.write(requests.get(url=img_link, headers=headers).content)
                        numbers += 1
                    if '![]({})'.format(img_src[0]) not in text_data_list:
                        text_data_list.append('![]({})'.format(img_src[0]))

            self.convertToMd(text_data_list)

            # 爬取该网页所有目录链接
            e_son_node = new_e_obj.xpath("//div[@class='css-1dbjc4n r-11q2w3b r-1yzf0co']//@href")
            # 筛选出子目录
            for href in e_son_node:
                # print("ww--->", href.split('/')[1], '  , len--->', len(href.split('/')))
                if new_name == href.split('/')[len(href.split('/'))-2]:
                    descendant_href_list.append(href)
                    print('second_link--->', href)
                else:
                    continue

            if descendant_href_list:
                for son_link in descendant_href_list:
                    son_catalog_name = son_link.split('/')[len(son_link.split('/'))-1]
                    son_catalog_link = url + son_link
                    try:
                        second_res = requests.get(url=son_catalog_link, headers=headers)
                    except Exception as e:
                        print("[start_spider_second]ERROR--->", e)
                    else:
                        text_data_list.clear()
                        second_label = "@second_" + son_catalog_name
                        text_data_list.append(second_label)
                        second_r_str = second_res.text
                        second_e_obj = etree.HTML(second_r_str)
                        second_e_data = second_e_obj.xpath("//div[@data-key]/@data-key")
                        try:
                            second_e_data.pop(0)
                        except Exception as e:
                            print("[second_e_data]ERROR--->", e)
                        for key in second_e_data:
                            actual_text = second_e_obj.xpath("//div[@data-key='{}']//text()".format(key))
                            strong_text = second_e_obj.xpath("//div[@data-key='{}']//strong//text()".format(key))
                            img_src = second_e_obj.xpath("//div[@data-key='{}']//img/@src".format(key))
                            href_link = second_e_obj.xpath("//div[@data-key]//a//text()")
                            if len(actual_text) > 1:
                                for element in actual_text:
                                    if href_link:
                                        for link in href_link:
                                            if link == element:
                                                _href = second_e_obj.xpath("//div[@data-key]//a/@href")
                                                text_data_list.append('[{}]({})'.format(element, _href[0]))
                                            else:
                                                text_data_list.append(element)
                                    else:
                                        text_data_list.append(element)
                            else:
                                if actual_text:
                                    text_data_list.append(actual_text[0])
                            if strong_text:
                                for s_text in strong_text:
                                    if s_text in text_data_list:
                                        text_data_list[text_data_list.index(s_text)] = '**{}**'.format(s_text)
                                        # if s_text == text_data_list[actual_text.index(s_text)]:
                                        #     text_data_list[text_data_list.index(s_text)] = '**{}**'.format(s_text)
                            # if actual_text:
                            #     text_data_list.append(actual_text[0])
                            # if strong_text:
                            #     text_data_list.append(strong_text[0])
                            if img_src:
                                numbers = 0
                                img_name = img_path + son_catalog_name + str(numbers) + '.jpg'
                                for img_link in img_src:
                                    with open(img_name, 'wb') as f:
                                        f.write(requests.get(url=img_link, headers=headers).content)
                                    numbers += 1
                                if '![]({})'.format(img_src[0]) not in text_data_list:
                                    text_data_list.append('![]({})'.format(img_src[0]))
                        self.convertToMd(text_data_list)

                        # 判断是否有三级目录
                        third_son_node = second_e_obj.xpath("//div[@class='css-1dbjc4n r-11q2w3b r-1yzf0co']//@href")
                        descendant_href_list_2 = []
                        for third_link in third_son_node:
                            if son_catalog_name == third_link.split('/')[len(third_link.split('/')) - 2]:
                                descendant_href_list_2.append(third_link)
                                print('third_link--->', third_link)
                            else:
                                continue
                        # 三级目录存在
                        if descendant_href_list_2:
                            for son_link_2 in descendant_href_list_2:
                                third_son_name = son_link_2.split('/')[len(son_link_2.split('/')) - 1]
                                third_son_link = url + son_link_2
                                try:
                                    third_res = requests.get(url=third_son_link, headers=headers)
                                except Exception as e:
                                    print("[start_spider_third]EROOR--->", e)
                                else:
                                    text_data_list.clear()
                                    third_label = "@third_" + third_son_name
                                    text_data_list.append(third_label)
                                    third_r_str = third_res.text
                                    third_e_obj = etree.HTML(third_r_str)
                                    third_e_data = third_e_obj.xpath("//div[@data-key]/@data-key")
                                    try:
                                        third_e_data.pop(0)
                                    except Exception as e:
                                        print('[third_e_data]ERROR--->', e)
                                    for key in third_e_data:
                                        actual_text = third_e_obj.xpath("//div[@data-key='{}']//text()".format(key))
                                        strong_text = third_e_obj.xpath("//div[@data-key='{}']//strong//text()".format(key))
                                        img_src = third_e_obj.xpath("//div[@data-key='{}']//img/@src".format(key))
                                        href_link = third_e_obj.xpath("//div[@data-key]//a//text()")
                                        if len(actual_text) > 1:
                                            for element in actual_text:
                                                if href_link:
                                                    for link in href_link:
                                                        if link == element:
                                                            _href = third_e_obj.xpath("//div[@data-key]//a/@href")
                                                            text_data_list.append('[{}]({})'.format(element, _href[0]))
                                                        else:
                                                            text_data_list.append(element)
                                                else:
                                                    text_data_list.append(element)
                                        else:
                                            if actual_text:
                                                text_data_list.append(actual_text[0])
                                        if strong_text:
                                            for s_text in strong_text:
                                                if s_text in text_data_list:
                                                    text_data_list[text_data_list.index(s_text)] = '**{}**'.format(
                                                        s_text)
                                        # if strong_text:
                                        #     if strong_text[0] == actual_text[actual_text.index(strong_text[0])]:
                                        #         text_data_list[actual_text.index(strong_text[0])] = '**{}**'.\
                                        #             format(strong_text[0])

                                            # if actual_text:
                                            #     for ele in actual_text:
                                            #         for s_ele in strong_text:
                                            #             if ele != s_ele:
                                            #                 text_data_list.append('**{}**'.format(s_ele))
                                            #             else:
                                            #                 if text_data_list[-1] == s_ele:
                                            #                     text_data_list.pop(-1)
                                            #                     text_data_list.append('**{}**'.format(s_ele))
                                            #                 else:
                                            #                     index = text_data_list.index(ele)
                                            #                     text_data_list[index] = '**{}**'.format(s_ele)
                                                # if actual_text[0] != strong_text[0]:
                                                #     text_data_list.append('**{}**'.format(strong_text[0]))
                                                # else:
                                                #     text_data_list.pop(-1)
                                                #     text_data_list.append('**{}**'.format(strong_text[0]))
                                            # else:
                                            #     text_data_list.append('**{}**'.format(strong_text[0]))
                                        #     text_data_list.append(actual_text[0])
                                        # if strong_text:
                                        #     text_data_list.append(strong_text[0])
                                        if img_src:
                                            numbers = 0
                                            img_name = img_path + third_son_name + str(numbers) + '.jpg'
                                            for img_link in img_src:
                                                with open(img_name, 'wb') as f:
                                                    f.write(requests.get(url=img_link, headers=headers).content)
                                                numbers += 1
                                            if '![]({})'.format(img_src[0]) not in text_data_list:
                                                text_data_list.append('![]({})'.format(img_src[0]))

                                    self.convertToMd(text_data_list)
            return

    # 获取introduction内容
    def getIntroduction(self, intro_e_obj):
        introduction_text_list.append('@first_Introduction')
        for key in data_offset_key_list:
            real_text = intro_e_obj.xpath("//div[@dir='auto']//span[@data-offset-key='{}']//text()".format(key))
            introduction_text_list.append(real_text[0])
            # self.save_data(introduction_text_list)
        self.convertToMd(introduction_text_list)
        return

    def convertToMd(self, data_list):
        save_path = '../src/gitbook/'
        filename = 'gitbooks.md'
        content = ''
        if not os.path.exists(save_path):
            os.makedirs(save_path)
        try:
            if data_list:
                data_list = self.data_clear(data_list)
                for text in data_list:
                    content = content + text + '\n\n'
                content = re.sub("@first_", "# ", content)
                content = re.sub("@second_", "## ", content)
                content = re.sub("@third_", "### ", content)
                # content.replace('\n', '').replace('.&tail&', '. \n\n').replace('&tail&', '')
                with open(save_path + filename, 'a', encoding='utf8') as f:
                    f.write(content)
        except Exception as e:
            print('[convertToMd]ERROR--->', e)

    # 数据去重
    @staticmethod
    def data_clear(data_list):
        new_data_list = []
        for old_data in data_list:
            if old_data not in new_data_list:
                new_data_list.append(old_data)
        return new_data_list

if __name__ == '__main__':
    crawl = crawl_gitBook()
    etree_obj = crawl.getParentCatalog(url, ips, headers)
    crawl.getIntroduction(etree_obj)
    count = 0
    for data in catalog_list_1:
        if count >= 1:
            first_label = '@first_' + data['catalog_name']
            crawl.start_spider(data['catalog_link'], data['catalog_name'], first_label)
            # if count == 3:
            #     break
        count += 1








'''
    默认配色： 
        Front:#CCCCCC
        Back:#0C0C0C
'''